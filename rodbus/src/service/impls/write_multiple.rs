use crate::client::message::Promise;
use crate::error::details::ADUParseError;
use crate::error::Error;
use crate::service::traits::ParseRequest;
use crate::service::traits::Serialize;
use crate::types::{AddressRange, WriteMultiple};
use crate::util::cursor::{ReadCursor, WriteCursor};

pub(crate) struct MultipleWrite<T>
where
    WriteMultiple<T>: Serialize,
{
    request: WriteMultiple<T>,
    promise: Promise<AddressRange>,
}

impl<T> MultipleWrite<T>
where
    WriteMultiple<T>: Serialize,
{
    pub(crate) fn new(request: WriteMultiple<T>, promise: Promise<AddressRange>) -> Self {
        Self { request, promise }
    }

    pub(crate) fn serialize(&self, cursor: &mut WriteCursor) -> Result<(), Error> {
        self.request.serialize(cursor)
    }

    pub(crate) fn failure(self, err: Error) {
        self.promise.failure(err)
    }

    pub(crate) fn handle_response(self, cursor: ReadCursor) {
        let result = self.parse_all(cursor);
        self.promise.complete(result)
    }

    fn parse_all(&self, mut cursor: ReadCursor) -> Result<AddressRange, Error> {
        let range = AddressRange::parse(&mut cursor)?;
        if range != self.request.range {
            return Err(Error::BadResponse(ADUParseError::ReplyEchoMismatch));
        }
        cursor.expect_empty()?;
        Ok(range)
    }
}