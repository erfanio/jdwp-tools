#![feature(let_chains)]
use clap::{Parser, Subcommand};
use jdwp_lib::{Client, Event, Value};

/// Simple debugger to set a breakpoint and print a variable when it's hit. The cli subcommands
/// determine what variable to print.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// JDWP address of the JVM. For Android use `adb forward tcp:<HOST_PORT> jdwp:<PID>` and pass
    /// '127.0.0.1:<HOST_PORT>' here.
    #[arg(short, long)]
    address: String,
    /// Fully qualified path of target method for the breakpoint, e.g. `java.lang.String.length`.
    #[arg(short, long)]
    target_method: String,
    /// Print stack trace as well.
    #[arg(short, long, default_value_t = true)]
    print_stack_trace: bool,
    #[command(subcommand)]
    variable_to_print: PrintCommands,
}

/// Variable type to print
#[derive(Debug, Subcommand)]
enum PrintCommands {
    /// Print a class member variable.
    Class { variable_name: String },
    /// Print a local (stack) variable.
    Stack { variable_name: String },
}

fn main() {
    let args = Args::parse();
    let (class, method) = args.target_method.rsplit_once(".").unwrap_or_else(||
        panic!(
            "Failed to extract class and methods from '{}'. Make sure you follow the `<FULL_CLASS_PATH>.<METHOD>` format.",
            args.target_method
        )
    );

    let mut client = Client::new(&args.address).unwrap();
    let version = client.command_version().unwrap();
    println!("Version {:?}", version);

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
            if let Event::Breakpoint {
                thread, location, ..
            } = event
            {
                println!("{:?}", args.variable_to_print);
                match args.variable_to_print {
                    PrintCommands::Class { ref variable_name } => {
                        println!("Class var is not supported!")
                    }
                    PrintCommands::Stack { ref variable_name } => {
                        let vars = client
                            .command_variable_table(location.class_id, location.method_id)
                            .unwrap();
                        let target_var = vars
                            .iter()
                            .find(|&v| v.name == *variable_name)
                            .unwrap_or_else(|| {
                                panic!(
                                    "{} variable name should exist in {}",
                                    variable_name, args.target_method
                                )
                            });
                        println!("{:?}", target_var);
                        let frames = client.command_frames(thread).unwrap();
                        let (frame_id, _) = frames.get(0).expect("This shouldn't happen! Expected at least 1 frame in the stack frame in JVM!");
                        let slots = vec![(
                            target_var.slot,
                            target_var.signature.bytes().nth(0).unwrap(),
                        )];
                        let values = client
                            .command_stack_get_values(thread, *frame_id, slots)
                            .unwrap();
                        let target_value = values.get(0).expect("This shouldn't happen! The JVM didn't return a value for target variable");

                        let sys_ref_id = client
                            .get_class_id("Ljava/lang/System;".to_string())
                            .unwrap();
                        let fields = client.command_fields(sys_ref_id).unwrap();
                        let field = fields.iter().find(|&v| v.name == "err").expect(
                            "This shouldn't happen! Cannot find System.err on the target JVM",
                        );
                        println!("{:?}", field);
                        let sys_err_values = client
                            .command_ref_get_values(sys_ref_id, vec![field.field_id])
                            .unwrap();
                        let sys_err_val = sys_err_values.get(0).expect(
                            "This shouldn't happen! Expected at least 1 value in System class!",
                        );
                        let sys_err_obj_id = if let Value::Object(object_id) = sys_err_val {
                            object_id
                        } else {
                            panic!("This shouldn't happen! The value of System.err is somehow not a object!")
                        };
                        println!("{:?}", sys_err_obj_id);
                        let (_, sys_err_class_id) =
                            client.command_obj_ref_type(*sys_err_obj_id).unwrap();
                        let (println_class_id, println_method_id) = client
                            .get_method_id(
                                sys_err_class_id,
                                "println".to_string(),
                                Some("(Ljava/lang/Object;)V".to_string()),
                            )
                            .unwrap();
                        client
                            .command_obj_invoke_method(
                                *sys_err_obj_id,
                                thread,
                                println_class_id,
                                println_method_id,
                                vec![target_value.clone()],
                            )
                            .unwrap();
                    }
                }
                if args.print_stack_trace {
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
        }
        client.command_resume().unwrap();
    }
}
