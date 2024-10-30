#![feature(let_chains)]
use clap::Parser;
use jdwp_lib::{Client, Event};

/// Simple debugger which prints a stack trace when target methods are called.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// JDWP address of the JVM. For Android use `adb forward tcp:<HOST_PORT> jdwp:<PID>` and pass
    /// '127.0.0.1:<HOST_PORT>' here.
    #[arg(short, long)]
    address: String,
    /// Fully qualified path of target methods for the breakpoints, e.g. `java.lang.String.length`.
    #[arg(short, long, num_args=1..)]
    target_methods: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let mut client = Client::new(&args.address).unwrap();
    let version = client.command_version().unwrap();
    println!("Version {:?}", version);

    for class_method in args.target_methods {
        let (class, method) = class_method.rsplit_once(".").unwrap_or_else(||
            panic!(
                "Failed to extract class and methods from '{}'. Make sure you follow the `<FULL_CLASS_PATH>.<METHOD>` format.",
                class_method
            )
        );

        let class_id = client
            .get_class_id(format!("L{};", class.to_string().replace(".", "/")))
            .unwrap();
        let (class_id, method_id) = client
            .get_method_id(class_id, method.to_string(), None)
            .unwrap();
        let breakpoint_reply = client.set_breakpoint(class_id, method_id, 0);
        match breakpoint_reply {
            Ok(r) => println!("Breakpoint set! Request ID {:?}", r),
            Err(e) => panic!("Breakpoint failed! Error {:?}", e),
        }
    }
    loop {
        let events = {
            if let Ok(es) = client.pull_pending_events()
                && es.len() > 0
            {
                es
            } else {
                client.listen_for_events().unwrap()
            }
        };
        println!("Events {:?}", events);
        for event in events {
            println!("{:?}", event);
            if let Event::Breakpoint { thread, .. } = event {
                let class_id = client
                    .get_class_id("Ljava/lang/Thread;".to_string())
                    .unwrap();
                let (class_id, method_id) = client
                    .get_method_id(class_id, "dumpStack".to_string(), Some("()V".to_string()))
                    .unwrap();
                client
                    .command_class_invoke_method(class_id, method_id, thread, vec![])
                    .unwrap();
            }
        }
        client.command_resume().unwrap();
    }
}
