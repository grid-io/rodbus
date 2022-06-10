use crate::common::buffer::ReadBuffer;
use crate::common::cursor::WriteCursor;
use crate::common::frame::{Frame, FrameDestination, FrameFormatter, FrameHeader, FrameParser};
use crate::common::function::FunctionCode;
use crate::common::traits::Serialize;
use crate::decode::FrameDecodeLevel;
use crate::error::{FrameParseError, RequestError};
use crate::types::UnitId;

pub(crate) mod constants {
    pub(crate) const HEADER_LENGTH: usize = 1;
    pub(crate) const FUNCTION_CODE_LENGTH: usize = 1;
    pub(crate) const CRC_LENGTH: usize = 2;
    pub(crate) const MAX_FRAME_LENGTH: usize =
        HEADER_LENGTH + crate::common::frame::constants::MAX_ADU_LENGTH + CRC_LENGTH;
}

/// precomputes the CRC table as a constant!
const CRC: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_MODBUS);

#[derive(Clone, Copy)]
enum ParserType {
    Request,
    Response,
}

#[derive(Clone, Copy)]
enum ParseState {
    Start,
    ReadFullBody(FrameDestination, usize), // unit_id, length of rest
    ReadToOffsetForLength(FrameDestination, usize), // unit_id, length to length
}

#[derive(Clone, Copy)]
enum LengthMode {
    /// The length is always the same (without function code)
    Fixed(usize),
    /// You need to read X more bytes. The last byte contains the number of extra bytes to read after that
    Offset(usize),
    /// Unknown function code, can't determine the size
    Unknown,
}

pub(crate) struct RtuParser {
    state: ParseState,
    parser_type: ParserType,
}

pub(crate) struct RtuFormatter {
    buffer: [u8; constants::MAX_FRAME_LENGTH],
}

impl RtuFormatter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0; constants::MAX_FRAME_LENGTH],
        }
    }
}

impl RtuParser {
    pub(crate) fn new_request_parser() -> Self {
        Self {
            state: ParseState::Start,
            parser_type: ParserType::Request,
        }
    }

    pub(crate) fn new_response_parser() -> Self {
        Self {
            state: ParseState::Start,
            parser_type: ParserType::Response,
        }
    }

    // Returns how to calculate the length of the body
    fn length_mode(&self, function_code: u8) -> LengthMode {
        // Check exception (only valid for responses)
        if matches!(self.parser_type, ParserType::Response) && function_code & 0x80 != 0 {
            return LengthMode::Fixed(1);
        }

        // Parse function code
        let function_code = match FunctionCode::get(function_code) {
            Some(code) => code,
            None => return LengthMode::Unknown,
        };

        match self.parser_type {
            ParserType::Request => match function_code {
                FunctionCode::ReadCoils => LengthMode::Fixed(4),
                FunctionCode::ReadDiscreteInputs => LengthMode::Fixed(4),
                FunctionCode::ReadHoldingRegisters => LengthMode::Fixed(4),
                FunctionCode::ReadInputRegisters => LengthMode::Fixed(4),
                FunctionCode::WriteSingleCoil => LengthMode::Fixed(4),
                FunctionCode::WriteSingleRegister => LengthMode::Fixed(4),
                FunctionCode::WriteMultipleCoils => LengthMode::Offset(5),
                FunctionCode::WriteMultipleRegisters => LengthMode::Offset(5),
            },
            ParserType::Response => match function_code {
                FunctionCode::ReadCoils => LengthMode::Offset(1),
                FunctionCode::ReadDiscreteInputs => LengthMode::Offset(1),
                FunctionCode::ReadHoldingRegisters => LengthMode::Offset(1),
                FunctionCode::ReadInputRegisters => LengthMode::Offset(1),
                FunctionCode::WriteSingleCoil => LengthMode::Fixed(4),
                FunctionCode::WriteSingleRegister => LengthMode::Fixed(4),
                FunctionCode::WriteMultipleCoils => LengthMode::Fixed(4),
                FunctionCode::WriteMultipleRegisters => LengthMode::Fixed(4),
            },
        }
    }
}

impl FrameParser for RtuParser {
    fn max_frame_size(&self) -> usize {
        constants::MAX_FRAME_LENGTH
    }

    fn parse(
        &mut self,
        cursor: &mut ReadBuffer,
        decode_level: FrameDecodeLevel,
    ) -> Result<Option<Frame>, RequestError> {
        match self.state {
            ParseState::Start => {
                if cursor.len() < 2 {
                    return Ok(None);
                }

                let unit_id = UnitId::new(cursor.read_u8()?);
                let destination = if unit_id == UnitId::broadcast() {
                    FrameDestination::Broadcast
                } else {
                    FrameDestination::UnitId(unit_id)
                };

                if unit_id.is_rtu_reserved() {
                    tracing::warn!("received reserved unit ID {}, violating Modbus RTU spec. Passing it through nevertheless.", unit_id);
                }

                tracing::debug!("UnitID: {}", unit_id);

                // We don't consume the function code to avoid an unecessary copy of the receive buffer later on
                let raw_function_code = cursor.peek_at(0)?;

                self.state = match self.length_mode(raw_function_code) {
                    LengthMode::Fixed(length) => ParseState::ReadFullBody(destination, length),
                    LengthMode::Offset(offset) => {
                        ParseState::ReadToOffsetForLength(destination, offset)
                    }
                    LengthMode::Unknown => {
                        return Err(RequestError::BadFrame(
                            FrameParseError::UnknownFunctionCode(raw_function_code),
                        ))
                    }
                };

                self.parse(cursor, decode_level)
            }
            ParseState::ReadToOffsetForLength(destination, offset) => {
                if cursor.len() < constants::FUNCTION_CODE_LENGTH + offset {
                    return Ok(None);
                }

                // Get the complete size
                let extra_bytes_to_read =
                    cursor.peek_at(constants::FUNCTION_CODE_LENGTH + offset - 1)? as usize;
                self.state = ParseState::ReadFullBody(destination, offset + extra_bytes_to_read);

                self.parse(cursor, decode_level)
            }
            ParseState::ReadFullBody(destination, length) => {
                if constants::FUNCTION_CODE_LENGTH + length
                    > crate::common::frame::constants::MAX_ADU_LENGTH
                {
                    return Err(RequestError::BadFrame(FrameParseError::FrameLengthTooBig(
                        constants::FUNCTION_CODE_LENGTH + length,
                        crate::common::frame::constants::MAX_ADU_LENGTH,
                    )));
                }

                if cursor.len() < constants::FUNCTION_CODE_LENGTH + length + constants::CRC_LENGTH {
                    return Ok(None);
                }

                let frame = {
                    let data = cursor.read(constants::FUNCTION_CODE_LENGTH + length)?;
                    let mut frame = Frame::new(FrameHeader::new_rtu_header(destination));
                    frame.set(data);
                    frame
                };
                let received_crc = cursor.read_u16_le()?;

                // Calculate CRC
                let expected_crc = {
                    let mut digest = CRC.digest();
                    digest.update(&[destination.value()]);
                    digest.update(frame.payload());
                    digest.finalize()
                };

                // Check CRC
                if received_crc != expected_crc {
                    return Err(RequestError::BadFrame(
                        FrameParseError::CrcValidationFailure(received_crc, expected_crc),
                    ));
                }

                if decode_level.enabled() {
                    tracing::info!(
                        "RTU RX - {}",
                        RtuDisplay::new(decode_level, destination, frame.payload(), received_crc)
                    );
                }

                self.state = ParseState::Start;
                Ok(Some(frame))
            }
        }
    }

    fn reset(&mut self) {
        self.state = ParseState::Start;
    }
}

impl FrameFormatter for RtuFormatter {
    fn format_impl(
        &mut self,
        header: FrameHeader,
        msg: &dyn Serialize,
        decode_level: FrameDecodeLevel,
    ) -> Result<usize, RequestError> {
        // Do some validation
        if let FrameDestination::UnitId(unit_id) = header.destination {
            if unit_id.is_rtu_reserved() {
                tracing::warn!(
                    "Sending a message to a reserved unit ID {} violates Modbus RTU spec",
                    unit_id
                )
            }
        }

        // Write the message
        let end_position = {
            let mut cursor = WriteCursor::new(self.buffer.as_mut());

            cursor.write_u8(header.destination.value())?;
            msg.serialize(&mut cursor)?;

            cursor.position()
        };

        // Calculate the CRC
        let crc = CRC.checksum(&self.buffer[0..end_position]);

        // Write the CRC
        {
            let mut cursor = WriteCursor::new(self.buffer.as_mut());
            cursor.seek_from_start(end_position)?;
            cursor.write_u16_le(crc)?;
        }

        // Logging
        if decode_level.enabled() {
            tracing::info!(
                "RTU TX - {}",
                RtuDisplay::new(
                    decode_level,
                    header.destination,
                    &self.buffer[constants::HEADER_LENGTH..end_position],
                    crc
                )
            );
        }

        Ok(end_position + constants::CRC_LENGTH)
    }

    fn get_full_buffer_impl(&self, size: usize) -> Option<&[u8]> {
        self.buffer.get(..size)
    }

    fn get_payload_impl(&self, size: usize) -> Option<&[u8]> {
        self.buffer
            .get(constants::HEADER_LENGTH..size - constants::CRC_LENGTH)
    }
}

struct RtuDisplay<'a> {
    level: FrameDecodeLevel,
    destination: FrameDestination,
    data: &'a [u8],
    crc: u16,
}

impl<'a> RtuDisplay<'a> {
    fn new(
        level: FrameDecodeLevel,
        destination: FrameDestination,
        data: &'a [u8],
        crc: u16,
    ) -> Self {
        RtuDisplay {
            level,
            destination,
            data,
            crc,
        }
    }
}

impl<'a> std::fmt::Display for RtuDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "dest: {} crc: {:#06X} (len = {})",
            self.destination,
            self.crc,
            self.data.len() - 1,
        )?;
        if self.level.payload_enabled() {
            crate::common::phys::format_bytes(f, self.data)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use crate::common::frame::FramedReader;
    use crate::common::phys::PhysLayer;
    use crate::tokio::test::*;
    use crate::DecodeLevel;

    use super::*;

    const UNIT_ID: u8 = 0x2A;

    const READ_COILS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x01,    // function code
        0x00, 0x10, // starting address
        0x00, 0x13, // qty of outputs
        0x7A, 0x19, // crc
    ];

    const READ_COILS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x01,    // function code
        0x03,    // byte count
        0xCD, 0x6B, 0x05, // output status
        0x44, 0x99, // crc
    ];

    const READ_DISCRETE_INPUTS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x02,    // function code
        0x00, 0x10, // starting address
        0x00, 0x13, // qty of outputs
        0x3E, 0x19, // crc
    ];

    const READ_DISCRETE_INPUTS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x02,    // function code
        0x03,    // byte count
        0xCD, 0x6B, 0x05, // output status
        0x00, 0x99, // crc
    ];

    const READ_HOLDING_REGISTERS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x03,    // function code
        0x00, 0x10, // starting address
        0x00, 0x03, // qty of registers
        0x02, 0x15, // crc
    ];

    const READ_HOLDING_REGISTERS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x03,    // function code
        0x06,    // byte count
        0x12, 0x34, 0x56, 0x78, 0x23, 0x45, // register values
        0x30, 0x60, // crc
    ];

    const READ_INPUT_REGISTERS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x04,    // function code
        0x00, 0x10, // starting address
        0x00, 0x03, // qty of registers
        0xB7, 0xD5, // crc
    ];

    const READ_INPUT_REGISTERS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x04,    // function code
        0x06,    // byte count
        0x12, 0x34, 0x56, 0x78, 0x23, 0x45, // register values
        0x71, 0x86, // crc
    ];

    const WRITE_SINGLE_COIL_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x05,    // function code
        0x00, 0x10, // output address
        0xFF, 0x00, // output value
        0x8B, 0xE4, // crc
    ];

    const WRITE_SINGLE_COIL_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x05,    // function code
        0x00, 0x10, // output address
        0xFF, 0x00, // output value
        0x8B, 0xE4, // crc
    ];

    const WRITE_SINGLE_REGISTER_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x06,    // function code
        0x00, 0x10, // output address
        0x12, 0x34, // output value
        0x83, 0x63, // crc
    ];

    const WRITE_SINGLE_REGISTER_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x06,    // function code
        0x00, 0x10, // output address
        0x12, 0x34, // output value
        0x83, 0x63, // crc
    ];

    const WRITE_MULTIPLE_COILS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x0F,    // function code
        0x00, 0x10, // starting address
        0x00, 0x0A, // qty of outputs
        0x02, // byte count
        0x12, 0x34, // output values
        0x00, 0x2E, // crc
    ];

    const WRITE_MULTIPLE_COILS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x0F,    // function code
        0x00, 0x10, // starting address
        0x00, 0x0A, // qty of outputs
        0xD2, 0x12, // crc
    ];

    const WRITE_MULTIPLE_REGISTERS_REQUEST: &[u8] = &[
        UNIT_ID, // unit id
        0x10,    // function code
        0x00, 0x10, // starting address
        0x00, 0x02, // qty of outputs
        0x04, // byte count
        0x12, 0x34, 0x56, 0x78, // output values
        0x07, 0x73, // crc
    ];

    const WRITE_MULTIPLE_REGISTERS_RESPONSE: &[u8] = &[
        UNIT_ID, // unit id
        0x10,    // function code
        0x00, 0x10, // starting address
        0x00, 0x02, // qty of outputs
        0x46, 0x16, // crc
    ];

    const ALL_REQUESTS: &[&[u8]] = &[
        READ_COILS_REQUEST,
        READ_DISCRETE_INPUTS_REQUEST,
        READ_HOLDING_REGISTERS_REQUEST,
        READ_INPUT_REGISTERS_REQUEST,
        WRITE_SINGLE_COIL_REQUEST,
        WRITE_SINGLE_REGISTER_REQUEST,
        WRITE_MULTIPLE_COILS_REQUEST,
        WRITE_MULTIPLE_REGISTERS_REQUEST,
    ];

    const ALL_RESPONSES: &[&[u8]] = &[
        READ_COILS_RESPONSE,
        READ_DISCRETE_INPUTS_RESPONSE,
        READ_HOLDING_REGISTERS_RESPONSE,
        READ_INPUT_REGISTERS_RESPONSE,
        WRITE_SINGLE_COIL_RESPONSE,
        WRITE_SINGLE_REGISTER_RESPONSE,
        WRITE_MULTIPLE_COILS_RESPONSE,
        WRITE_MULTIPLE_REGISTERS_RESPONSE,
    ];

    fn assert_can_parse_frame<T: FrameParser>(mut reader: FramedReader<T>, frame: &[u8]) {
        let (io, mut io_handle) = io::mock();
        let mut layer = PhysLayer::new_mock(io);
        let mut task = spawn(reader.next_frame(&mut layer, DecodeLevel::nothing()));

        io_handle.read(frame);
        if let Poll::Ready(received_frame) = task.poll() {
            let received_frame = received_frame.unwrap();
            assert_eq!(received_frame.header.tx_id, None);
            assert_eq!(
                received_frame.header.destination,
                FrameDestination::new_unit_id(UNIT_ID)
            );
            assert_eq!(
                received_frame.payload(),
                &frame[1..frame.len() - constants::CRC_LENGTH]
            );
        } else {
            panic!("Task not ready");
        }
    }

    #[test]
    fn can_parse_request_frames() {
        for request in ALL_REQUESTS {
            let reader = FramedReader::new(RtuParser::new_request_parser());
            assert_can_parse_frame(reader, request);
        }
    }

    #[test]
    fn can_parse_response_frames() {
        for response in ALL_RESPONSES {
            let reader = FramedReader::new(RtuParser::new_response_parser());
            assert_can_parse_frame(reader, response);
        }
    }

    #[test]
    fn can_parse_huge_response() {
        let mut huge_response = vec![
            UNIT_ID, // unit id
            0x03,    // function code (read holding registers)
            0xFA,    // byte count (max value, 125 registers)
        ];

        // Push the data
        for _ in 0..0xFA {
            huge_response.push(0x00)
        }

        // Write the correct CRC
        let crc = CRC.checksum(&huge_response);
        huge_response.push((crc & 0x00FF) as u8);
        huge_response.push(((crc & 0xFF00) >> 8) as u8);

        let reader = FramedReader::new(RtuParser::new_response_parser());
        assert_can_parse_frame(reader, &huge_response);
    }

    #[test]
    fn refuse_response_too_big() {
        let mut huge_response = vec![
            UNIT_ID, // unit id
            0x03,    // function code (read holding registers)
            0xFB,    // byte count (one more than allowed)
        ];

        // Push the data
        for _ in 0..0xFB {
            huge_response.push(0x00)
        }

        // Write the correct CRC
        let crc = CRC.checksum(&huge_response);
        huge_response.push((crc & 0x00FF) as u8);
        huge_response.push(((crc & 0xFF00) >> 8) as u8);

        let reader = FramedReader::new(RtuParser::new_response_parser());
        assert_can_parse_frame(reader, &huge_response);
    }

    fn assert_can_parse_frame_byte_per_byte<T: FrameParser>(
        mut reader: FramedReader<T>,
        frame: &[u8],
    ) {
        let (io, mut io_handle) = io::mock();
        let mut layer = PhysLayer::new_mock(io);
        let mut task = spawn(reader.next_frame(&mut layer, DecodeLevel::nothing()));

        // Send bytes to parser byte per byte
        for byte in frame.into_iter().take(frame.len() - 1) {
            io_handle.read(&[*byte]);
            assert!(matches!(task.poll(), Poll::Pending));
        }

        // Last byte
        io_handle.read(&[frame[frame.len() - 1]]);
        if let Poll::Ready(received_frame) = task.poll() {
            let received_frame = received_frame.unwrap();
            assert_eq!(received_frame.header.tx_id, None);
            assert_eq!(
                received_frame.header.destination,
                FrameDestination::new_unit_id(UNIT_ID)
            );
            assert_eq!(
                received_frame.payload(),
                &frame[1..frame.len() - constants::CRC_LENGTH]
            );
        } else {
            panic!("Task not ready");
        }
    }

    #[test]
    fn can_parse_request_frames_byte_per_byte() {
        for request in ALL_REQUESTS {
            let reader = FramedReader::new(RtuParser::new_request_parser());
            assert_can_parse_frame_byte_per_byte(reader, request);
        }
    }

    #[test]
    fn can_parse_response_frames_byte_per_byte() {
        for response in ALL_RESPONSES {
            let reader = FramedReader::new(RtuParser::new_response_parser());
            assert_can_parse_frame_byte_per_byte(reader, response);
        }
    }

    fn assert_can_parse_two_frames<T: FrameParser>(mut reader: FramedReader<T>, frame: &[u8]) {
        let (io, mut io_handle) = io::mock();
        let mut layer = PhysLayer::new_mock(io);

        // Build single array with two identical frames
        let duplicate_frames = frame
            .iter()
            .chain(frame.iter())
            .copied()
            .collect::<Vec<_>>();

        // Last byte
        io_handle.read(duplicate_frames.as_slice());

        // First frame
        {
            let mut task = spawn(reader.next_frame(&mut layer, DecodeLevel::nothing()));
            if let Poll::Ready(received_frame) = task.poll() {
                let received_frame = received_frame.unwrap();
                assert_eq!(received_frame.header.tx_id, None);
                assert_eq!(
                    received_frame.header.destination,
                    FrameDestination::new_unit_id(UNIT_ID)
                );
                assert_eq!(
                    received_frame.payload(),
                    &frame[1..frame.len() - constants::CRC_LENGTH]
                );
            } else {
                panic!("Task not ready");
            }
        }

        // Second frame
        {
            let mut task = spawn(reader.next_frame(&mut layer, DecodeLevel::nothing()));
            if let Poll::Ready(received_frame) = task.poll() {
                let received_frame = received_frame.unwrap();
                assert_eq!(received_frame.header.tx_id, None);
                assert_eq!(
                    received_frame.header.destination,
                    FrameDestination::new_unit_id(UNIT_ID)
                );
                assert_eq!(
                    received_frame.payload(),
                    &frame[1..frame.len() - constants::CRC_LENGTH]
                );
            } else {
                panic!("Task not ready");
            }
        }
    }

    #[test]
    fn can_parse_two_request_frames() {
        for request in ALL_REQUESTS {
            let reader = FramedReader::new(RtuParser::new_request_parser());
            assert_can_parse_two_frames(reader, request);
        }
    }

    #[test]
    fn can_parse_two_response_frames() {
        for response in ALL_RESPONSES {
            let reader = FramedReader::new(RtuParser::new_response_parser());
            assert_can_parse_two_frames(reader, response);
        }
    }

    #[test]
    fn fails_on_wrong_crc() {
        const READ_COILS_REQUEST_WRONG_CRC: &[u8] = &[
            UNIT_ID, // unit id
            0x01,    // function code
            0x00, 0x10, // starting address
            0x00, 0x13, // qty of outputs
            0xFF, 0xFF, // wrong crc
        ];

        let mut reader = FramedReader::new(RtuParser::new_request_parser());
        let (io, mut io_handle) = io::mock();
        let mut layer = PhysLayer::new_mock(io);
        let mut task = spawn(reader.next_frame(&mut layer, DecodeLevel::nothing()));

        io_handle.read(READ_COILS_REQUEST_WRONG_CRC);
        if let Poll::Ready(received_frame) = task.poll() {
            assert!(matches!(
                received_frame,
                Err(RequestError::BadFrame(
                    FrameParseError::CrcValidationFailure(_, _)
                ))
            ));
        } else {
            panic!("Task not ready");
        }
    }

    struct MockMessage<'a> {
        frame: &'a [u8],
    }

    impl<'a> Serialize for MockMessage<'a> {
        fn serialize(self: &Self, cursor: &mut WriteCursor) -> Result<(), RequestError> {
            for byte in &self.frame[1..self.frame.len() - 2] {
                cursor.write_u8(*byte)?;
            }
            Ok(())
        }
    }

    fn assert_frame_formatting(frame: &[u8]) {
        let mut formatter = RtuFormatter::new();
        let msg = MockMessage { frame };
        let header = FrameHeader::new_rtu_header(FrameDestination::UnitId(UnitId::new(42)));
        let size = formatter
            .format_impl(header, &msg, FrameDecodeLevel::Nothing)
            .unwrap();
        let output = formatter.get_full_buffer_impl(size).unwrap();

        assert_eq!(output, frame);
    }

    #[test]
    fn can_format_request_frames() {
        for request in ALL_REQUESTS {
            assert_frame_formatting(request);
        }
    }

    #[test]
    fn can_format_response_frames() {
        for response in ALL_RESPONSES {
            assert_frame_formatting(response);
        }
    }
}