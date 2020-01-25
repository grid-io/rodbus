use crate::parse_socket_address;
use crate::user_data::UserData;
use rodbus::error::details::ExceptionCode;
use rodbus::server::handler::{ServerHandler, ServerHandlerMap};
use rodbus::types::{AddressRange, Indexed, UnitId, WriteCoils, WriteRegisters};
use std::os::raw::c_void;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

// if this returns true, we update the underlying value automatically
type WriteSingleCallback<T> = Option<unsafe extern "C" fn(T, u16, *mut c_void) -> bool>;
type WriteMultipleCallback<T> =
    Option<unsafe extern "C" fn(*const T, u16, u16, *mut c_void) -> bool>;

struct Data {
    bo: Vec<bool>,
    bi: Vec<bool>,
    ao: Vec<u16>,
    ai: Vec<u16>,
}

#[repr(C)]
pub struct Callbacks {
    write_single_coil_cb: WriteSingleCallback<bool>,
    write_single_register_cb: WriteSingleCallback<u16>,
    write_multiple_coils: WriteMultipleCallback<bool>,
    write_multiple_registers: WriteMultipleCallback<u16>,
}

struct FFIHandler {
    data: Data,
    callbacks: Callbacks,
    user_data: UserData,
}

#[repr(C)]
pub struct Sizes {
    num_coils: u16,
    num_discrete_inputs: u16,
    num_holding_registers: u16,
    num_input_registers: u16,
}

#[no_mangle]
pub extern "C" fn create_sizes(
    num_coils: u16,
    num_discrete_inputs: u16,
    num_holding_registers: u16,
    num_input_registers: u16,
) -> Sizes {
    Sizes::new(
        num_coils,
        num_discrete_inputs,
        num_holding_registers,
        num_input_registers,
    )
}

impl Sizes {
    fn new(
        num_coils: u16,
        num_discrete_inputs: u16,
        num_holding_registers: u16,
        num_input_registers: u16,
    ) -> Self {
        Self {
            num_coils,
            num_discrete_inputs,
            num_holding_registers,
            num_input_registers,
        }
    }
}

impl Data {
    pub(crate) fn new(sizes: Sizes) -> Self {
        Self {
            bo: vec![false; sizes.num_coils as usize],
            bi: vec![false; sizes.num_discrete_inputs as usize],
            ao: vec![0; sizes.num_holding_registers as usize],
            ai: vec![0; sizes.num_input_registers as usize],
        }
    }
}

impl Callbacks {
    pub(crate) fn new(
        write_single_coil_cb: WriteSingleCallback<bool>,
        write_single_register_cb: WriteSingleCallback<u16>,
        write_multiple_coils: WriteMultipleCallback<bool>,
        write_multiple_registers: WriteMultipleCallback<u16>,
    ) -> Self {
        Self {
            write_single_coil_cb,
            write_single_register_cb,
            write_multiple_coils,
            write_multiple_registers,
        }
    }
}

#[no_mangle]
pub extern "C" fn create_callbacks(
    write_single_coil_cb: WriteSingleCallback<bool>,
    write_single_register_cb: WriteSingleCallback<u16>,
    write_multiple_coils: WriteMultipleCallback<bool>,
    write_multiple_registers: WriteMultipleCallback<u16>,
) -> Callbacks {
    Callbacks::new(
        write_single_coil_cb,
        write_single_register_cb,
        write_multiple_coils,
        write_multiple_registers,
    )
}

impl FFIHandler {
    pub fn new(data: Data, callbacks: Callbacks, user_data: *mut c_void) -> Self {
        Self {
            data,
            callbacks,
            user_data: UserData::new(user_data),
        }
    }

    fn write_single<T>(
        pair: Indexed<T>,
        vec: &mut Vec<T>,
        callback: WriteSingleCallback<T>,
        user_data: &mut UserData,
    ) -> Result<(), ExceptionCode>
    where
        T: Copy,
    {
        match callback {
            Some(func) => match vec.get_mut(pair.index as usize) {
                Some(value) => unsafe {
                    if func(pair.value, pair.index, user_data.value) {
                        *value = pair.value
                    }
                    Ok(())
                },
                None => Err(ExceptionCode::IllegalDataValue),
            },
            None => Err(ExceptionCode::IllegalFunction),
        }
    }

    fn write_multiple<T>(
        items: &[T],
        range: AddressRange,
        vec: &mut Vec<T>,
        callback: WriteMultipleCallback<T>,
        user_data: &mut UserData,
    ) -> Result<(), ExceptionCode>
    where
        T: Copy,
    {
        match callback {
            Some(func) => match vec.get_mut(range.to_range_or_exception()?) {
                Some(value) => unsafe {
                    // TODO - can this be done well w/o allocating?
                    if func(items.as_ptr(), range.count, range.start, user_data.value) {
                        value.copy_from_slice(items)
                    }
                    Ok(())
                },
                None => Err(ExceptionCode::IllegalDataValue),
            },
            None => Err(ExceptionCode::IllegalFunction),
        }
    }
}

impl ServerHandler for FFIHandler {
    fn read_coils(&mut self, range: AddressRange) -> Result<&[bool], ExceptionCode> {
        Self::get_range_of(&self.data.bo, range)
    }

    fn read_discrete_inputs(&mut self, range: AddressRange) -> Result<&[bool], ExceptionCode> {
        Self::get_range_of(&self.data.bi, range)
    }

    fn read_holding_registers(&mut self, range: AddressRange) -> Result<&[u16], ExceptionCode> {
        Self::get_range_of(&self.data.ao, range)
    }

    fn read_input_registers(&mut self, range: AddressRange) -> Result<&[u16], ExceptionCode> {
        Self::get_range_of(&self.data.ai, range)
    }

    fn write_single_coil(&mut self, pair: Indexed<bool>) -> Result<(), ExceptionCode> {
        Self::write_single(
            pair,
            &mut self.data.bo,
            self.callbacks.write_single_coil_cb,
            &mut self.user_data,
        )
    }

    fn write_single_register(&mut self, pair: Indexed<u16>) -> Result<(), ExceptionCode> {
        Self::write_single(
            pair,
            &mut self.data.ao,
            self.callbacks.write_single_register_cb,
            &mut self.user_data,
        )
    }

    fn write_multiple_coils(&mut self, values: WriteCoils) -> Result<(), ExceptionCode> {
        let vec: Vec<bool> = values.iterator.collect();
        Self::write_multiple(
            vec.as_slice(),
            values.range,
            &mut self.data.bo,
            self.callbacks.write_multiple_coils,
            &mut self.user_data,
        )
    }

    fn write_multiple_registers(&mut self, values: WriteRegisters) -> Result<(), ExceptionCode> {
        let vec: Vec<u16> = values.iterator.collect();
        Self::write_multiple(
            vec.as_slice(),
            values.range,
            &mut self.data.ao,
            self.callbacks.write_multiple_registers,
            &mut self.user_data,
        )
    }
}

pub struct Handler {
    runtime: *mut Runtime,
    wrapper: Arc<Mutex<Box<FFIHandler>>>,
}

pub struct Updater<'a> {
    guard: tokio::sync::MutexGuard<'a, Box<FFIHandler>>,
}

#[no_mangle]
pub extern "C" fn create_handler(
    runtime: *mut Runtime,
    sizes: Sizes,
    callbacks: Callbacks,
    user_data: *mut c_void,
) -> *mut Handler {
    let handler = FFIHandler::new(Data::new(sizes), callbacks, user_data);
    Box::into_raw(Box::new(Handler {
        runtime,
        wrapper: handler.wrap(),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn acquire_updater<'a>(handler: *mut Handler) -> *mut Updater<'a> {
    let handler = handler.as_mut().unwrap();
    let updater = handler.runtime.as_mut().unwrap().block_on(async move {
        Updater {
            guard: handler.wrapper.lock().await,
        }
    });
    Box::into_raw(Box::new(updater))
}

#[no_mangle]
pub unsafe extern "C" fn update_handler(
    handler: *mut Handler,
    callback: Option<unsafe extern "C" fn(*mut Updater)>,
) {
    if let Some(func) = callback {
        let handler = handler.as_mut().unwrap();
        let wrapper = handler.wrapper.clone();
        handler.runtime.as_mut().unwrap().block_on(async move {
            let mut updater = Updater {
                guard: wrapper.lock().await,
            };
            func(&mut updater)
        });
    }
}

#[no_mangle]
pub unsafe extern "C" fn release_updater(updater: *mut Updater) {
    if !updater.is_null() {
        Box::from_raw(updater);
    };
}

#[no_mangle]
pub unsafe extern "C" fn update_coil(updater: *mut Updater, value: bool, index: u16) -> bool {
    let updater = updater.as_mut().unwrap();
    if let Some(data) = updater.guard.data.bo.get_mut(index as usize) {
        *data = value;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_server(
    runtime: *mut Runtime,
    address: *const std::os::raw::c_char,
    unit_id: u8,
    handler: *mut Handler,
) -> bool {
    let rt = runtime.as_mut().unwrap();

    let addr = match parse_socket_address(address) {
        Some(addr) => addr,
        None => return false,
    };

    let listener = match rt.block_on(async move { tokio::net::TcpListener::bind(addr).await }) {
        Err(err) => {
            log::error!("Unable to bind listener: {}", err);
            return false;
        }
        Ok(listener) => listener,
    };

    let handler = handler.as_mut().unwrap().wrapper.clone();

    rt.spawn(rodbus::server::create_tcp_server_task(
        100,
        listener,
        ServerHandlerMap::single(UnitId::new(unit_id), handler),
    ));

    true
}
