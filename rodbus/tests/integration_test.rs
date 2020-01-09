extern crate rodbus;

use rodbus::prelude::*;
use std::net::SocketAddr;
use std::str::FromStr;

use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use std::time::Duration;

struct Handler {
    pub coils: [bool; 10],
    pub discrete_inputs: [bool; 10],
    pub holding_registers: [u16; 10],
    pub input_registers: [u16; 10],
}

impl Handler {
    fn new() -> Self {
        Self {
            coils: [false; 10],
            discrete_inputs: [false; 10],
            holding_registers: [0; 10],
            input_registers: [0; 10],
        }
    }
}

impl ServerHandler for Handler {
    fn read_coils(&mut self, range: AddressRange) -> Result<&[bool], details::ExceptionCode> {
        Self::get_range_of(self.coils.as_ref(), range)
    }

    fn read_discrete_inputs(
        &mut self,
        range: AddressRange,
    ) -> Result<&[bool], details::ExceptionCode> {
        Self::get_range_of(self.discrete_inputs.as_ref(), range)
    }

    fn read_holding_registers(
        &mut self,
        range: AddressRange,
    ) -> Result<&[u16], details::ExceptionCode> {
        Self::get_range_of(self.holding_registers.as_ref(), range)
    }

    fn read_input_registers(
        &mut self,
        range: AddressRange,
    ) -> Result<&[u16], details::ExceptionCode> {
        Self::get_range_of(self.input_registers.as_ref(), range)
    }

    fn write_single_coil(&mut self, value: Indexed<bool>) -> Result<(), details::ExceptionCode> {
        let idx = value.index as usize;
        if idx < self.coils.len() {
            self.coils[idx] = value.value;
            Ok(())
        } else {
            Err(details::ExceptionCode::IllegalDataAddress)
        }
    }

    fn write_single_register(&mut self, value: Indexed<u16>) -> Result<(), details::ExceptionCode> {
        let idx = value.index as usize;
        if idx < self.holding_registers.len() {
            self.holding_registers[idx] = value.value;
            Ok(())
        } else {
            Err(details::ExceptionCode::IllegalDataAddress)
        }
    }

    fn write_multiple_coils(
        &mut self,
        range: AddressRange,
        iter: &BitIterator,
    ) -> Result<(), details::ExceptionCode> {
        // TODO - validation?
        let mut address = range.start as usize;
        for value in *iter {
            self.coils[address] = value;
            address += 1;
        }
        Ok(())
    }

    fn write_multiple_registers(
        &mut self,
        range: AddressRange,
        iter: &RegisterIterator,
    ) -> Result<(), details::ExceptionCode> {
        // TODO - validation?
        let mut address = range.start as usize;
        for value in *iter {
            self.holding_registers[address] = value;
            address += 1;
        }
        Ok(())
    }
}

fn with_client_and_server<T>(f: T)
where
    T: FnOnce(Runtime, AsyncSession, Arc<Mutex<Box<Handler>>>) -> (),
{
    let handler = Handler::new().wrap();
    let addr = SocketAddr::from_str("127.0.0.1:40000").unwrap();
    let mut rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind(addr)).unwrap();

    let map = ServerHandlerMap::single(UnitId::new(1), handler.clone());

    rt.spawn(create_tcp_server_task(1, listener, map));

    let (channel, task) = create_handle_and_task(addr, 10, strategy::default());

    rt.spawn(task);

    let session = channel.create_session(UnitId::new(0x01), Duration::from_secs(1));

    f(rt, session, handler)
}

#[test]
fn can_read_and_write_values() {
    with_client_and_server(|mut rt, mut session, handler| {
        // set up some known initial state for the read-only values
        {
            let mut guard = rt.block_on(handler.lock());
            guard.discrete_inputs[0] = true;
            guard.input_registers[0] = 0xCAFE;
        }

        assert_eq!(
            rt.block_on(session.read_discrete_inputs(AddressRange::new(0, 2)))
                .unwrap(),
            vec![Indexed::new(0, true), Indexed::new(1, false)]
        );

        assert_eq!(
            rt.block_on(session.read_input_registers(AddressRange::new(0, 2)))
                .unwrap(),
            vec![Indexed::new(0, 0xCAFE), Indexed::new(1, 0x0000)]
        );

        // do a single coil write and verify that it was written by reading it
        assert_eq!(
            rt.block_on(session.write_single_coil(Indexed::new(1, true)))
                .unwrap(),
            Indexed::new(1, true)
        );
        assert_eq!(
            rt.block_on(session.read_coils(AddressRange::new(0, 2)))
                .unwrap(),
            vec![Indexed::new(0, false), Indexed::new(1, true)]
        );

        // do a single register write and verify that it was written by reading it
        assert_eq!(
            rt.block_on(session.write_single_register(Indexed::new(1, 0xABCD)))
                .unwrap(),
            Indexed::new(1, 0xABCD)
        );
        assert_eq!(
            rt.block_on(session.read_holding_registers(AddressRange::new(0, 2)))
                .unwrap(),
            vec![Indexed::new(0, 0x0000), Indexed::new(1, 0xABCD)]
        );

        // write multiple coils and verify that they were written
        assert_eq!(
            rt.block_on(
                session.write_multiple_coils(WriteMultiple::new(0, vec![true, true, true]))
            )
            .unwrap(),
            AddressRange::new(0, 3)
        );
        assert_eq!(
            rt.block_on(session.read_coils(AddressRange::new(0, 3)))
                .unwrap(),
            vec![
                Indexed::new(0, true),
                Indexed::new(1, true),
                Indexed::new(2, true)
            ]
        );

        // write registers and verify that they were written
        assert_eq!(
            rt.block_on(
                session
                    .write_multiple_registers(WriteMultiple::new(0, vec![0x0102, 0x0304, 0x0506]))
            )
            .unwrap(),
            AddressRange::new(0, 3)
        );
        assert_eq!(
            rt.block_on(session.read_holding_registers(AddressRange::new(0, 3)))
                .unwrap(),
            vec![
                Indexed::new(0, 0x0102),
                Indexed::new(1, 0x0304),
                Indexed::new(2, 0x0506)
            ]
        );
    });
}
