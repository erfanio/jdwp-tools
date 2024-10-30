use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::prelude::*;
use std::io::Error;
use std::io::Result;
use std::net::TcpStream;
use std::str;

pub struct Client {
    stream: TcpStream,
    last_command_id: u32,
    recv_cmd_queue: VecDeque<Command>,
    all_classes_cache: HashMap<String, AllClassesReply>,
    methods_cache: HashMap<u64, HashMap<String, Vec<MethodsReply>>>,
}

/*
 * Data structures to contain decoded data from command/reply data field.
 */
#[derive(Debug)]
pub struct VersionReply {
    pub description: String,
    pub jdwp_major: i32,
    pub jdwp_minor: i32,
    pub vm_version: String,
    pub vm_name: String,
}

#[derive(Debug)]
pub struct AllClassesReply {
    pub reference_type: ReferenceType,
    pub reference_id: u64,
    pub class_status: u32,
}

#[derive(Debug)]
pub struct MethodsReply {
    pub method_id: u64,
    pub name: String,
    pub signature: String,
    pub flags: u32,
}

#[derive(Debug)]
pub struct VariableTableReply {
    pub code_index: u64,
    pub name: String,
    pub signature: String,
    pub length: u32,
    pub slot: i32,
}

#[derive(Debug)]
pub struct FieldReply {
    pub field_id: u64,
    pub name: String,
    pub signature: String,
    pub flags: u32,
}

#[derive(Debug)]
pub enum Event {
    Breakpoint {
        request_id: i32,
        thread: u64,
        location: Location,
    },
    Unknown,
}

#[derive(Debug)]
pub struct Location {
    pub ltype: ReferenceType,
    // TODO remove later
    pub class_id: u64,
    pub method_id: u64,
    pub index: u64,
}

#[derive(Debug)]
pub enum ReferenceType {
    Class = 1,
    Interface = 2,
    Array = 3,
}

#[derive(Debug, Clone)]
pub enum Value {
    Object(u64),
}

#[derive(Debug)]
enum Packet {
    Command(Command),
    Reply(Reply),
}

#[derive(Debug)]
struct Command {
    flags: u8,
    command_set: u8,
    command: u8,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Reply {
    flags: u8,
    error_code: u16,
    data: Vec<u8>,
}

// https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
const HANDSHAKE: &[u8] = b"JDWP-Handshake";

// https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html
const COMMAND_VERSION: (u8, u8) = (1, 1);
const COMMAND_ALL_CLASSES: (u8, u8) = (1, 3);
const COMMAND_ID_SIZES: (u8, u8) = (1, 7);
const COMMAND_RESUME: (u8, u8) = (1, 9);
const COMMAND_FIELDS: (u8, u8) = (2, 4);
const COMMAND_METHODS: (u8, u8) = (2, 5);
const COMMAND_REF_GET_VALUES: (u8, u8) = (2, 6);
const COMMAND_SUPERCLASS: (u8, u8) = (3, 1);
const COMMAND_CLASS_INVOKE_METHOD: (u8, u8) = (3, 3);
const COMMAND_METHOD_VARIABLE_TABLE: (u8, u8) = (6, 2);
const COMMAND_OBJ_REF_TYPE: (u8, u8) = (9, 1);
const COMMAND_OBJ_INVOKE_METHOD: (u8, u8) = (9, 6);
const COMMAND_FRAMES: (u8, u8) = (11, 6);
const COMMAND_EVENT_SET: (u8, u8) = (15, 1);
const COMMAND_STACK_GET_VALUES: (u8, u8) = (16, 1);

// https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventKind
const EVENT_BREAKPOINT: u8 = 2;

// https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest
const MODIFIER_LOCATION_ONLY: u8 = 7;

// https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_SuspendPolicy
const SUSPEND_POLICY_THREAD: u8 = 1;

// https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Tag
const TAG_OBJECT: u8 = 76;

impl Client {
    pub fn new(address: &str) -> Result<Client> {
        let stream = TcpStream::connect(address)?;
        let mut client = Client {
            stream,
            last_command_id: 0,
            recv_cmd_queue: VecDeque::new(),
            all_classes_cache: HashMap::new(),
            methods_cache: HashMap::new(),
        };

        client.stream.write_all(HANDSHAKE)?;
        let mut reply = [0; HANDSHAKE.len()];
        client.stream.read_exact(&mut reply)?;
        if reply != HANDSHAKE {
            return Err(Error::other(format!(
                "Handshake failed! Expected '{}' but got '{}'",
                HANDSHAKE.escape_ascii().to_string(),
                reply.escape_ascii().to_string()
            )));
        }

        // Verify all ID sizes are 8 bytes.
        // TODO: Support other sizes.
        let (command_set, command) = COMMAND_ID_SIZES;
        client.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data: vec![],
        })?;

        let reply = client.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (field_id_size, remaining_data) = client.read_int(&reply.data)?;
        let (method_id_size, remaining_data) = client.read_int(remaining_data)?;
        let (object_id_size, remaining_data) = client.read_int(remaining_data)?;
        let (reference_type_id_size, remaining_data) = client.read_int(remaining_data)?;
        let (frame_id_size, _) = client.read_int(remaining_data)?;
        if field_id_size != 8 {
            return Err(Error::other(format!("The target JVM uses {} byte size for reference type ID but this library only supports 8 byte size.", method_id_size)));
        }
        if method_id_size != 8 {
            return Err(Error::other(format!("The target JVM uses {} byte size for method ID but this library only supports 8 byte size.", method_id_size)));
        }
        if object_id_size != 8 {
            return Err(Error::other(format!("The target JVM uses {} byte size for object ID but this library only supports 8 byte size.", method_id_size)));
        }
        if reference_type_id_size != 8 {
            return Err(Error::other(format!("The target JVM uses {} byte size for reference type ID but this library only supports 8 byte size.", method_id_size)));
        }
        if frame_id_size != 8 {
            return Err(Error::other(format!("The target JVM uses {} byte size for reference type ID but this library only supports 8 byte size.", method_id_size)));
        }

        // Pre-fetch loaded classes.
        client.command_all_classes()?;

        Ok(client)
    }

    pub fn command_version(&mut self) -> Result<VersionReply> {
        let (command_set, command) = COMMAND_VERSION;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data: vec![],
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (description, remaining_data) = self.read_string(&reply.data)?;
        let (jdwp_major, remaining_data) = self.read_int(remaining_data)?;
        let (jdwp_minor, remaining_data) = self.read_int(remaining_data)?;
        let (vm_version, remaining_data) = self.read_string(remaining_data)?;
        let (vm_name, _) = self.read_string(remaining_data)?;
        Ok(VersionReply {
            description,
            jdwp_major,
            jdwp_minor,
            vm_version,
            vm_name,
        })
    }

    pub fn command_resume(&mut self) -> Result<()> {
        let (command_set, command) = COMMAND_RESUME;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data: vec![],
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        Ok(())
    }

    pub fn command_class_invoke_method(
        &mut self,
        class_id: u64,
        method_id: u64,
        thread_id: u64,
        args: Vec<Value>,
    ) -> Result<()> {
        // https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_InvokeMethod
        let mut data: Vec<u8> = vec![];
        data.extend(class_id.to_be_bytes());
        data.extend(thread_id.to_be_bytes());
        data.extend(method_id.to_be_bytes());
        // Number of arguments
        data.extend((args.len() as i32).to_be_bytes());
        for arg in args {
            data.extend(self.write_value(arg));
        }
        // No InvokeOptions
        data.extend((0 as i32).to_be_bytes());

        let (command_set, command) = COMMAND_CLASS_INVOKE_METHOD;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        Ok(())
    }

    pub fn command_obj_invoke_method(
        &mut self,
        object_id: u64,
        thread_id: u64,
        class_id: u64,
        method_id: u64,
        args: Vec<Value>,
    ) -> Result<()> {
        // https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_InvokeMethod
        let mut data: Vec<u8> = vec![];
        data.extend(object_id.to_be_bytes());
        data.extend(thread_id.to_be_bytes());
        data.extend(class_id.to_be_bytes());
        data.extend(method_id.to_be_bytes());
        // Number of arguments
        data.extend((args.len() as i32).to_be_bytes());
        for arg in args {
            data.extend(self.write_value(arg));
        }
        // No InvokeOptions
        data.extend((0 as i32).to_be_bytes());

        let (command_set, command) = COMMAND_OBJ_INVOKE_METHOD;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        Ok(())
    }

    pub fn set_breakpoint(&mut self, class_id: u64, method_id: u64, index: u64) -> Result<i32> {
        // See https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest
        let mut data: Vec<u8> = vec![];
        data.push(EVENT_BREAKPOINT);
        data.push(SUSPEND_POLICY_THREAD);
        // Number of modifiers
        data.extend((1 as i32).to_be_bytes());
        data.push(MODIFIER_LOCATION_ONLY);
        data.push(ReferenceType::Class as u8);
        data.extend(class_id.to_be_bytes());
        data.extend(method_id.to_be_bytes());
        data.extend(index.to_be_bytes());

        let (command_set, command) = COMMAND_EVENT_SET;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (request_id, _) = self.read_int(&reply.data)?;
        Ok(request_id)
    }

    pub fn listen_for_events(&mut self) -> Result<Vec<Event>> {
        // Either pull from wire or recv_cmd_queue which has events received earlier.
        let command = {
            if let Some(c) = self.recv_cmd_queue.pop_front() {
                println!(
                    "[WARNING] {} events waiting to be pulled!",
                    self.recv_cmd_queue.len()
                );
                c
            } else if let Packet::Command(c) = self.receive_packet()? {
                c
            } else {
                // All commands are expected to wait for a reply. We should never see replies here
                // unless something weird is going on.
                panic!("Received an unexpected reply while waiting for a command!")
            }
        };
        self.decode_command(command)
    }

    pub fn pull_pending_events(&mut self) -> Result<Vec<Event>> {
        let mut events = vec![];
        while let Some(c) = self.recv_cmd_queue.pop_front() {
            events.extend(self.decode_command(c)?);
        }
        Ok(events)
    }

    pub fn command_variable_table(
        &mut self,
        class_id: u64,
        method_id: u64,
    ) -> Result<Vec<VariableTableReply>> {
        let (command_set, command) = COMMAND_METHOD_VARIABLE_TABLE;
        let mut data = vec![];
        data.extend(class_id.to_be_bytes().to_vec());
        data.extend(method_id.to_be_bytes().to_vec());
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (num_args, data) = self.read_int(&reply.data)?;
        let (num_vars, mut data) = self.read_int(data)?;
        println!(
            "[INFO] {} args and {} vars for class ID {} method ID {} fetched from JVM.",
            num_args, num_vars, class_id, method_id
        );
        let mut vars = vec![];
        for _ in 0..num_vars {
            let (code_index, remaining_data) = self.read_long(&data)?;
            let (name, remaining_data) = self.read_string(remaining_data)?;
            let (signature, remaining_data) = self.read_string(remaining_data)?;
            let (length, remaining_data) = self.read_uint(remaining_data)?;
            let (slot, remaining_data) = self.read_int(remaining_data)?;
            vars.push(VariableTableReply {
                code_index,
                name,
                signature,
                length,
                slot,
            });

            data = remaining_data;
        }
        Ok(vars)
    }

    pub fn command_fields(&mut self, class_id: u64) -> Result<Vec<FieldReply>> {
        let (command_set, command) = COMMAND_FIELDS;
        let data = class_id.to_be_bytes().to_vec();
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (num_fields, mut data) = self.read_int(&reply.data)?;
        println!(
            "[INFO] {} fields for class ID {} fetched from JVM.",
            num_fields, class_id
        );
        let mut fields = vec![];
        for _ in 0..num_fields {
            let (field_id, remaining_data) = self.read_field_id(&data)?;
            let (name, remaining_data) = self.read_string(remaining_data)?;
            let (signature, remaining_data) = self.read_string(remaining_data)?;
            let (flags, remaining_data) = self.read_uint(remaining_data)?;
            fields.push(FieldReply {
                field_id,
                name,
                signature,
                flags,
            });

            data = remaining_data;
        }
        Ok(fields)
    }

    pub fn command_ref_get_values(
        &mut self,
        reference_id: u64,
        field_ids: Vec<u64>,
    ) -> Result<Vec<Value>> {
        let (command_set, command) = COMMAND_REF_GET_VALUES;
        let mut data = vec![];
        data.extend(reference_id.to_be_bytes().to_vec());
        data.extend((field_ids.len() as i32).to_be_bytes().to_vec());
        for field_id in field_ids {
            data.extend(field_id.to_be_bytes());
        }
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (num_values, mut data) = self.read_int(&reply.data)?;
        let mut values = vec![];
        for _ in 0..num_values {
            let (value, remaining_data) = self.read_value(data)?;
            values.push(value);

            data = remaining_data;
        }
        Ok(values)
    }

    pub fn command_stack_get_values(
        &mut self,
        thread_id: u64,
        frame_id: u64,
        slots: Vec<(i32, u8)>,
    ) -> Result<Vec<Value>> {
        let (command_set, command) = COMMAND_STACK_GET_VALUES;
        let mut data = vec![];
        data.extend(thread_id.to_be_bytes().to_vec());
        data.extend(frame_id.to_be_bytes().to_vec());
        data.extend((slots.len() as i32).to_be_bytes().to_vec());
        for (slot, tag) in slots {
            data.extend(slot.to_be_bytes());
            data.push(tag);
        }
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (num_values, mut data) = self.read_int(&reply.data)?;
        let mut values = vec![];
        for _ in 0..num_values {
            let (value, remaining_data) = self.read_value(data)?;
            values.push(value);

            data = remaining_data;
        }
        Ok(values)
    }

    pub fn command_obj_ref_type(&mut self, object_id: u64) -> Result<(ReferenceType, u64)> {
        let (command_set, command) = COMMAND_OBJ_REF_TYPE;
        let data = object_id.to_be_bytes().to_vec();
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (ref_type, remaining_data) = self.read_ref_type(&reply.data)?;
        let (reference_id, _) = self.read_reference_id(remaining_data)?;
        Ok((ref_type, reference_id))
    }

    pub fn command_superclass(&mut self, class_id: u64) -> Result<u64> {
        let (command_set, command) = COMMAND_SUPERCLASS;
        let data = class_id.to_be_bytes().to_vec();
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (superclass_id, _) = self.read_reference_id(&reply.data)?;
        Ok(superclass_id)
    }

    pub fn command_frames(&mut self, thread_id: u64) -> Result<Vec<(u64, Location)>> {
        let (command_set, command) = COMMAND_FRAMES;
        let mut data = vec![];
        data.extend(thread_id.to_be_bytes().to_vec());
        data.extend((0 as i32).to_be_bytes().to_vec());
        data.extend((1 as i32).to_be_bytes().to_vec());
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        println!("[DEBUG] {:?}", reply);
        let (num_frames, mut data) = self.read_int(&reply.data)?;
        let mut frames = vec![];
        for _ in 0..num_frames {
            let (frame_id, remaining_data) = self.read_frame_id(data)?;
            let (location, remaining_data) = self.read_location(remaining_data)?;
            frames.push((frame_id, location));

            data = remaining_data;
        }
        Ok(frames)
    }

    pub fn get_class_id(&mut self, class_name: String) -> Result<u64> {
        if let Some(x) = self.all_classes_cache.get(&class_name) {
            Ok(x.reference_id)
        } else {
            self.command_all_classes()?;
            if let Some(x) = self.all_classes_cache.get(&class_name) {
                Ok(x.reference_id)
            } else {
                Err(Error::other(format!(
                    "Cannot find {} loaded on target JVM.",
                    class_name
                )))
            }
        }
    }

    pub fn get_method_id(
        &mut self,
        class_id: u64,
        method_name: String,
        signature: Option<String>,
    ) -> Result<(u64, u64)> {
        if let Some(Some(x)) = self
            .methods_cache
            .get(&class_id)
            .map(|x| x.get(&method_name))
        {
            if let Some(sig) = signature {
                Ok((
                    class_id,
                    x.iter().find(|&m| m.signature == sig).unwrap().method_id,
                ))
            } else {
                Ok((class_id, x.first().unwrap().method_id))
            }
        } else {
            self.command_methods(class_id)?;
            if let Some(Some(x)) = self
                .methods_cache
                .get(&class_id)
                .map(|x| x.get(&method_name))
            {
                if let Some(sig) = signature {
                    Ok((
                        class_id,
                        x.iter().find(|&m| m.signature == sig).unwrap().method_id,
                    ))
                } else {
                    Ok((class_id, x.first().unwrap().method_id))
                }
            } else {
                let superclass_id = self.command_superclass(class_id)?;
                self.get_method_id(superclass_id, method_name, signature)

                // Err(Error::other(format!(
                //     "Cannot find {} method on target JVM.",
                //     method_name
                // )))
            }
        }
    }

    fn decode_command(&self, command: Command) -> Result<Vec<Event>> {
        let mut events = vec![];
        // Don't care about suspend policy, ignoring the first byte.
        let num_events = u32::from_be_bytes(command.data[1..5].try_into().unwrap());
        println!("[INFO] Received {} event(s)", num_events);
        let mut data = &command.data[5..];
        for _ in 0..num_events {
            let event_kind: u8 = data[0];
            let remaining_data = &data[1..];
            match event_kind {
                EVENT_BREAKPOINT => {
                    println!(
                        "Breakpoint data {}",
                        remaining_data.escape_ascii().to_string()
                    );
                    let (request_id, remaining_data) = self.read_int(remaining_data)?;
                    let (thread, remaining_data) = self.read_object_id(remaining_data)?;
                    let (location, _) = self.read_location(remaining_data)?;
                    events.push(Event::Breakpoint {
                        request_id,
                        thread,
                        location,
                    });
                }
                // When we come across an unknown event we should just return immediately because
                // we can't correctly consume all the bytes from this event to proceed to the next
                // event.
                _ => {
                    return Ok(vec![Event::Unknown]);
                }
            };
            data = remaining_data;
        }
        Ok(events)
    }

    fn command_all_classes(&mut self) -> Result<()> {
        let (command_set, command) = COMMAND_ALL_CLASSES;
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data: vec![],
        })?;

        let reply = self.wait_for_reply()?;
        let (num_classes, mut data) = self.read_int(&reply.data)?;
        println!("[INFO] {} loaded classes fetched from JVM.", num_classes);
        self.all_classes_cache.clear();
        for _ in 0..num_classes {
            let (reference_type, remaining_data) = self.read_ref_type(data)?;
            let (reference_id, remaining_data) = self.read_reference_id(remaining_data)?;
            let (signature, remaining_data) = self.read_string(remaining_data)?;
            // TODO figure out a way to store the class_status bit field in an enum.
            let (class_status, remaining_data) = self.read_uint(remaining_data)?;
            println!("[VERBOSE] {} {}", signature, reference_id);
            self.all_classes_cache.insert(
                signature,
                AllClassesReply {
                    reference_type,
                    reference_id,
                    class_status,
                },
            );
            data = remaining_data;
        }
        Ok(())
    }

    fn command_methods(&mut self, class_id: u64) -> Result<()> {
        let (command_set, command) = COMMAND_METHODS;
        let data = class_id.to_be_bytes().to_vec();
        self.send_command(&Command {
            flags: 0,
            command_set,
            command,
            data,
        })?;

        let reply = self.wait_for_reply()?;
        let (num_methods, mut data) = self.read_int(&reply.data)?;
        println!(
            "[INFO] {} methods for class ID {} fetched from JVM.",
            num_methods, class_id
        );
        let mut methods: HashMap<String, Vec<MethodsReply>> = HashMap::new();
        for _ in 0..num_methods {
            let (method_id, remaining_data) = self.read_method_id(&data)?;
            let (name, remaining_data) = self.read_string(remaining_data)?;
            let (signature, remaining_data) = self.read_string(remaining_data)?;
            let (flags, remaining_data) = self.read_uint(remaining_data)?;
            let method = MethodsReply {
                method_id,
                name: name.clone(),
                signature,
                flags,
            };
            println!("{:?}", method);
            if let Some(v) = methods.get_mut(&name) {
                v.push(method);
            } else {
                methods.insert(name, vec![method]);
            }

            data = remaining_data;
        }
        self.methods_cache.insert(class_id, methods);
        Ok(())
    }

    fn send_command(&mut self, command: &Command) -> Result<()> {
        // Increment last packet ID when sending new packets.
        self.last_command_id += 1;

        // See https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
        let mut binary_packet: Vec<u8> = vec![];
        let packet_length: u32 = (command.data.len() + 11).try_into().unwrap();
        binary_packet.extend(packet_length.to_be_bytes());
        binary_packet.extend(self.last_command_id.to_be_bytes());
        binary_packet.push(command.flags);
        binary_packet.push(command.command_set);
        binary_packet.push(command.command);
        binary_packet.extend(&command.data);
        self.stream.write_all(&binary_packet)?;
        println!(
            "[DEBUG] Sent command packet (ID {}) {:?}",
            self.last_command_id, command
        );
        println!(
            "[DEBUG] Binary command packet {}",
            binary_packet.escape_ascii().to_string()
        );
        Ok(())
    }

    fn receive_packet(&mut self) -> Result<Packet> {
        let mut header = [0; 11];
        self.stream.read_exact(&mut header)?;
        let length = u32::from_be_bytes(header[..4].try_into().unwrap());
        let id = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let flags = header[8];

        let data_len: usize = (length - 11).try_into().unwrap();
        let mut data = vec![0; data_len];
        self.stream.read_exact(&mut data)?;

        // If the received packet is a reply, flag 0x80 will be set, otherwise this is a command
        // from the VM. The last two bytes of the header have different meanings depending on
        // whether it's a command or a reply.
        // See https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
        if flags == 0x80 {
            if id != self.last_command_id {
                panic!(
                    "Received a reply with ID {} but last command ID was {}",
                    id, self.last_command_id
                );
            }
            println!("[DEBUG] Received a reply packet.");
            let error_code = u16::from_be_bytes(header[9..11].try_into().unwrap());
            Ok(Packet::Reply(Reply {
                flags,
                error_code,
                data: Vec::from(data),
            }))
        } else {
            println!("[DEBUG] Received a command packet.");
            let (command_set, command) = (header[9], header[10]);
            Ok(Packet::Command(Command {
                flags,
                command_set,
                command,
                data: Vec::from(data),
            }))
        }
    }

    fn wait_for_reply(&mut self) -> Result<Reply> {
        loop {
            match self.receive_packet()? {
                Packet::Command(c) => {
                    println!("[WARNING] Recieved a new command while waiting for a reply.");
                    self.recv_cmd_queue.push_back(c);
                }
                Packet::Reply(r) => return Ok(r),
            }
        }
    }

    fn read_int<'a>(&self, data: &'a [u8]) -> Result<(i32, &'a [u8])> {
        if data.len() < 4 {
            Err(Error::other("Failed to read int from buffer"))
        } else {
            let int = i32::from_be_bytes(data[..4].try_into().unwrap());
            Ok((int, &data[4..]))
        }
    }

    fn read_uint<'a>(&self, data: &'a [u8]) -> Result<(u32, &'a [u8])> {
        if data.len() < 4 {
            Err(Error::other("Failed to read int from buffer"))
        } else {
            let int = u32::from_be_bytes(data[..4].try_into().unwrap());
            Ok((int, &data[4..]))
        }
    }

    fn read_long<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        if data.len() < 8 {
            Err(Error::other("Failed to read int from buffer"))
        } else {
            let int = u64::from_be_bytes(data[..8].try_into().unwrap());
            Ok((int, &data[8..]))
        }
    }

    fn read_ref_type<'a>(&self, data: &'a [u8]) -> Result<(ReferenceType, &'a [u8])> {
        if data.len() < 1 {
            Err(Error::other(
                "Failed to read reference type tag from buffer",
            ))
        } else {
            let ref_type = match data[0] {
                1 => ReferenceType::Class,
                2 => ReferenceType::Interface,
                3 => ReferenceType::Array,
                _ => {
                    return Err(Error::other(format!(
                        "Unknown reference type! Byte value {} is not a recognized reference type constant.",
                        data[0]
                    )))
                }
            };
            Ok((ref_type, &data[1..]))
        }
    }

    fn read_object_id<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        if data.len() < 8 {
            Err(Error::other(
                "Failed to read Object ID (i.e. thread ID, string ID, etc.) from buffer.",
            ))
        } else {
            let int = u64::from_be_bytes(data[..8].try_into().unwrap());
            Ok((int, &data[8..]))
        }
    }

    fn read_reference_id<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        // TODO: change once we support other sizes.
        self.read_object_id(data)
    }

    fn read_method_id<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        // TODO: change once we support other sizes.
        self.read_object_id(data)
    }

    fn read_field_id<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        // TODO: change once we support other sizes.
        self.read_object_id(data)
    }

    fn read_frame_id<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8])> {
        // TODO: change once we support other sizes.
        self.read_object_id(data)
    }

    fn read_string<'a>(&self, data: &'a [u8]) -> Result<(String, &'a [u8])> {
        let (str_len, remaining_data) = self.read_uint(data)?;
        let str_len: usize = str_len.try_into().unwrap();
        if remaining_data.len() < str_len {
            Err(Error::other("Failed to read String from buffer."))
        } else {
            let s = String::from_utf8((&remaining_data[..str_len]).to_vec())
                .map_err(|e| Error::other(e))?;
            Ok((s, &remaining_data[str_len..]))
        }
    }

    fn read_location<'a>(&self, data: &'a [u8]) -> Result<(Location, &'a [u8])> {
        if data.len() < 25 {
            Err(Error::other("Failed to read Location from buffer."))
        } else {
            let (ltype, remaining_data) = self.read_ref_type(&data)?;
            let (class_id, remaining_data) = self.read_object_id(&remaining_data)?;
            let (method_id, remaining_data) = self.read_object_id(&remaining_data)?;
            let (index, remaining_data) = self.read_object_id(&remaining_data)?;
            Ok((
                Location {
                    ltype,
                    class_id,
                    method_id,
                    index,
                },
                &remaining_data,
            ))
        }
    }

    fn read_value<'a>(&self, data: &'a [u8]) -> Result<(Value, &'a [u8])> {
        if data.len() < 1 {
            Err(Error::other("Failed to read value type tag from buffer"))
        } else {
            let tag = data[0];
            let data = &data[1..];
            match tag {
                TAG_OBJECT => {
                    let (object_id, remaining_data) = self.read_object_id(data)?;
                    Ok((Value::Object(object_id), remaining_data))
                }
                _ => Err(Error::other(format!(
                    "Unknown value type! Byte value {} is not a recognized value type constant.",
                    tag
                ))),
            }
        }
    }

    fn write_value(&self, v: Value) -> Vec<u8> {
        match v {
            Value::Object(id) => {
                let mut data: Vec<u8> = vec![TAG_OBJECT];
                println!("{:?}", id);
                data.extend(id.to_be_bytes().to_vec());
                data
            }
        }
    }
}
