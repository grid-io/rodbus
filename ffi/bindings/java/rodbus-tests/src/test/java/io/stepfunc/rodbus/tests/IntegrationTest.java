package io.stepfunc.rodbus.tests;

import io.stepfunc.rodbus.*;
import io.stepfunc.rodbus.Exception;
import io.stepfunc.rodbus.Runtime;
import org.joou.*;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.joou.Unsigned.*;

public class IntegrationTest {
    static final UByte UNIT_ID = ubyte(1);
    static final UInteger TIMEOUT_MS = uint(1000);
    static final int NUM_POINTS = 10;
    static final String ENDPOINT = "127.0.0.1:50000";

    static class TestWriteHandler implements WriteHandler {
        @Override
        public WriteResult writeSingleCoil(boolean value, UShort index, Database database) {
            if (database.updateCoil(index, value)) {
                return WriteResult.createSuccess();
            } else {
                return WriteResult.createException(Exception.ILLEGAL_DATA_ADDRESS);
            }
        }

        @Override
        public WriteResult writeSingleRegister(UShort value, UShort index, Database database) {
            if (database.updateHoldingRegister(index, value)) {
                return WriteResult.createSuccess();
            } else {
                return WriteResult.createException(Exception.ILLEGAL_DATA_ADDRESS);
            }
        }

        @Override
        public WriteResult writeMultipleCoils(UShort start, List<Bit> it, Database database) {
            for (Bit bit : it) {
                if (!database.updateCoil(bit.index, bit.value)) {
                    return WriteResult.createException(Exception.ILLEGAL_DATA_ADDRESS);
                }
            }

            return WriteResult.createSuccess();
        }

        @Override
        public WriteResult writeMultipleRegisters(UShort start, List<Register> it, Database database) {
            for (Register register : it) {
                if (!database.updateHoldingRegister(register.index, register.value)) {
                    return WriteResult.createException(Exception.ILLEGAL_DATA_ADDRESS);
                }
            }

            return WriteResult.createSuccess();
        }
    }

    @Test
    public void clientAndServerCommunication() throws ExecutionException, InterruptedException {
        final RuntimeConfig runtimeConfig = new RuntimeConfig();
        runtimeConfig.numCoreThreads = ushort(2);
        try(Runtime runtime = new Runtime(runtimeConfig)) {
            DeviceMap map = new DeviceMap();
            map.addEndpoint(UNIT_ID, new TestWriteHandler(), db -> {
                for(int i = 0; i < NUM_POINTS; i++) {
                    db.addCoil(ushort(i), false);
                    db.addDiscreteInput(ushort(i), false);
                    db.addHoldingRegister(ushort(i), ushort(0));
                    db.addInputRegister(ushort(i), ushort(0));
                }
            });

            Server server = Server.createTcpServer(runtime, ENDPOINT, ushort(100), map);
            Channel client = Channel.createTcpClient(runtime, ENDPOINT, ushort(10));

            // Set a unique pattern to test reads
            server.update(UNIT_ID, db -> {
                db.updateDiscreteInput(ushort(3), true);
                db.updateInputRegister(ushort(4), ushort(42));
            });

            testReadDiscreteInputs(client);
            testReadInputRegisters(client);
            testWriteSingleCoil(client);
            testWriteSingleRegister(client);
            testWriteMultipleCoils(client);
        }
    }

    private void testReadDiscreteInputs(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        AddressRange range = new AddressRange();
        range.start = ushort(2);
        range.count = ushort(3);

        BitReadResult result = client.readDiscreteInputs(range, param).toCompletableFuture().get();

        assertThat(result.result.summary).isEqualTo(Status.OK);
        assertThat(result.iterator).hasSize(3);
        assertThat(result.iterator.get(0).index).isEqualTo(ushort(2));
        assertThat(result.iterator.get(0).value).isEqualTo(false);
        assertThat(result.iterator.get(1).index).isEqualTo(ushort(3));
        assertThat(result.iterator.get(1).value).isEqualTo(true);
        assertThat(result.iterator.get(2).index).isEqualTo(ushort(4));
        assertThat(result.iterator.get(2).value).isEqualTo(false);

        // ======

        range.start = ushort(9);
        range.count = ushort(2);
        result = client.readDiscreteInputs(range, param).toCompletableFuture().get();

        assertThat(result.result.summary).isEqualTo(Status.EXCEPTION);
        assertThat(result.result.exception).isEqualTo(Exception.ILLEGAL_DATA_ADDRESS);
    }

    private void testReadInputRegisters(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        AddressRange range = new AddressRange();
        range.start = ushort(3);
        range.count = ushort(3);

        RegisterReadResult result = client.readInputRegisters(range, param).toCompletableFuture().get();

        assertThat(result.result.summary).isEqualTo(Status.OK);
        assertThat(result.iterator).hasSize(3);
        assertThat(result.iterator.get(0).index).isEqualTo(ushort(3));
        assertThat(result.iterator.get(0).value).isEqualTo(ushort(0));
        assertThat(result.iterator.get(1).index).isEqualTo(ushort(4));
        assertThat(result.iterator.get(1).value).isEqualTo(ushort(42));
        assertThat(result.iterator.get(2).index).isEqualTo(ushort(5));
        assertThat(result.iterator.get(2).value).isEqualTo(ushort(0));

        // ======

        range.start = ushort(10);
        range.count = ushort(1);
        result = client.readInputRegisters(range, param).toCompletableFuture().get();

        assertThat(result.result.summary).isEqualTo(Status.EXCEPTION);
        assertThat(result.result.exception).isEqualTo(Exception.ILLEGAL_DATA_ADDRESS);
    }

    private void testWriteSingleCoil(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        Bit bit = new Bit();
        bit.index = ushort(1);
        bit.value = true;

        ErrorInfo writeResult = client.writeSingleCoil(bit, param).toCompletableFuture().get();
        assertThat(writeResult.summary).isEqualTo(Status.OK);

        // ======

        AddressRange range = new AddressRange();
        range.start = ushort(0);
        range.count = ushort(2);

        BitReadResult readResult = client.readCoils(range, param).toCompletableFuture().get();

        assertThat(readResult.result.summary).isEqualTo(Status.OK);
        assertThat(readResult.iterator).hasSize(2);
        assertThat(readResult.iterator.get(0).index).isEqualTo(ushort(0));
        assertThat(readResult.iterator.get(0).value).isEqualTo(false);
        assertThat(readResult.iterator.get(1).index).isEqualTo(ushort(1));
        assertThat(readResult.iterator.get(1).value).isEqualTo(true);
    }

    private void testWriteSingleRegister(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        Register register = new Register();
        register.index = ushort(1);
        register.value = ushort(22);

        ErrorInfo writeResult = client.writeSingleRegister(register, param).toCompletableFuture().get();
        assertThat(writeResult.summary).isEqualTo(Status.OK);

        // ======

        AddressRange range = new AddressRange();
        range.start = ushort(0);
        range.count = ushort(2);

        RegisterReadResult readResult = client.readHoldingRegisters(range, param).toCompletableFuture().get();

        assertThat(readResult.result.summary).isEqualTo(Status.OK);
        assertThat(readResult.iterator).hasSize(2);
        assertThat(readResult.iterator.get(0).index).isEqualTo(ushort(0));
        assertThat(readResult.iterator.get(0).value).isEqualTo(ushort(0));
        assertThat(readResult.iterator.get(1).index).isEqualTo(ushort(1));
        assertThat(readResult.iterator.get(1).value).isEqualTo(ushort(22));
    }

    private void testWriteMultipleCoils(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        ErrorInfo writeResult = client.writeMultipleCoils(ushort(0), Arrays.asList(true, false, true), param).toCompletableFuture().get();
        assertThat(writeResult.summary).isEqualTo(Status.OK);

        // ======

        AddressRange range = new AddressRange();
        range.start = ushort(0);
        range.count = ushort(3);

        BitReadResult readResult = client.readCoils(range, param).toCompletableFuture().get();

        assertThat(readResult.result.summary).isEqualTo(Status.OK);
        assertThat(readResult.iterator).hasSize(3);
        assertThat(readResult.iterator.get(0).index).isEqualTo(ushort(0));
        assertThat(readResult.iterator.get(0).value).isEqualTo(true);
        assertThat(readResult.iterator.get(1).index).isEqualTo(ushort(1));
        assertThat(readResult.iterator.get(1).value).isEqualTo(false);
        assertThat(readResult.iterator.get(2).index).isEqualTo(ushort(2));
        assertThat(readResult.iterator.get(2).value).isEqualTo(true);
    }

    private void testWriteMultipleRegisters(Channel client) throws ExecutionException, InterruptedException {
        RequestParam param = new RequestParam();
        param.unitId = UNIT_ID;
        param.timeoutMs = TIMEOUT_MS;

        ErrorInfo writeResult = client.writeMultipleRegisters(ushort(0), Arrays.asList(ushort(0xCAFE), ushort(21), ushort(0xFFFF)), param).toCompletableFuture().get();
        assertThat(writeResult.summary).isEqualTo(Status.OK);

        // ======

        AddressRange range = new AddressRange();
        range.start = ushort(0);
        range.count = ushort(3);

        RegisterReadResult readResult = client.readHoldingRegisters(range, param).toCompletableFuture().get();

        assertThat(readResult.result.summary).isEqualTo(Status.OK);
        assertThat(readResult.iterator).hasSize(3);
        assertThat(readResult.iterator.get(0).index).isEqualTo(ushort(0));
        assertThat(readResult.iterator.get(0).value).isEqualTo(ushort(0xCAFE));
        assertThat(readResult.iterator.get(1).index).isEqualTo(ushort(1));
        assertThat(readResult.iterator.get(1).value).isEqualTo(ushort(21));
        assertThat(readResult.iterator.get(2).index).isEqualTo(ushort(2));
        assertThat(readResult.iterator.get(2).value).isEqualTo(ushort(0xFFFF));
    }
}
