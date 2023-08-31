use super::EventFdTrigger;
use crate::devices::bus::BusDevice;
use std::io::Write;
use vm_superio::{serial::SerialEvents, Serial, Trigger};

pub struct SerialWrapper<T: Trigger, EV: SerialEvents, W: Write> {
    pub serial: Serial<T, EV, W>,
}

pub struct SerialEventsWrapper {
    pub buffer_read_event_fd: Option<EventFdTrigger>,
}

impl SerialEvents for SerialEventsWrapper {
    fn buffer_read(&self) {}

    fn out_byte(&self) {}

    fn tx_lost_byte(&self) {}

    fn in_buffer_empty(&self) {}
}

impl<W: Write + Send + 'static> BusDevice
    for SerialWrapper<EventFdTrigger, SerialEventsWrapper, W>
{
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        data[0] = self.serial.read(offset as u8);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if let Err(e) = self.serial.write(offset as u8, data[0]) {
            println!("serial writing error: {:?}", e);
        }
    }
}

pub type SerialDevice = SerialWrapper<EventFdTrigger, SerialEventsWrapper, Box<dyn Write + Send>>;
