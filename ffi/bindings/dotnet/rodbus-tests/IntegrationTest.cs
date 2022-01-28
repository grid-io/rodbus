using Microsoft.VisualStudio.TestTools.UnitTesting;

using rodbus;
using System;
using System.Collections.Generic;
using System.Linq;

namespace rodbus_tests
{
    class WriteHandler : IWriteHandler
    {
        public WriteResult WriteSingleCoil(ushort index, bool value, Database database)
        {
            if (database.UpdateCoil(index, value))
            {
                return WriteResult.CreateSuccess();
            }
            else
            {
                return WriteResult.CreateException(rodbus.ModbusException.IllegalDataAddress);
            }
        }

        public WriteResult WriteSingleRegister(ushort index, ushort value, Database database)
        {
            if (database.UpdateHoldingRegister(index, value))
            {
                return WriteResult.CreateSuccess();
            }
            else
            {
                return WriteResult.CreateException(rodbus.ModbusException.IllegalDataAddress);
            }
        }

        public WriteResult WriteMultipleCoils(ushort start, ICollection<Bit> it, Database database)
        {
            foreach (var bit in it)
            {
                if (!database.UpdateCoil(bit.Index, bit.Value))
                {
                    return WriteResult.CreateException(rodbus.ModbusException.IllegalDataAddress);
                }
            }

            return WriteResult.CreateSuccess();
        }

        public WriteResult WriteMultipleRegisters(ushort start, ICollection<Register> it, Database database)
        {
            foreach (var bit in it)
            {
                if (!database.UpdateHoldingRegister(bit.Index, bit.Value))
                {
                    return WriteResult.CreateException(rodbus.ModbusException.IllegalDataAddress);
                }
            }

            return WriteResult.CreateSuccess();
        }
    }

    class DatabaseUpdate : IDatabaseCallback
    {
        readonly System.Action<Database> action;

        public DatabaseUpdate(System.Action<Database> action)
        {
            this.action = action;
        }

        public void Callback(Database database)
        {
            this.action.Invoke(database);
        }
    }

    [TestClass]
    public class IntegrationTest
    {
        private static readonly byte UNIT_ID = 1;
        private static readonly ushort NUM_POINTS = 10;
        private static readonly string ENDPOINT = "127.0.0.1:20000";
        private static readonly RequestParam param = new RequestParam(UNIT_ID, TimeSpan.FromSeconds(1));

        static void TestReadDiscreteInputs(Channel client)
        {
            var result = client.ReadDiscreteInputs(param, new AddressRange(2, 3)).Result;
            var resultList = result.Iterator.ToList();
            Assert.AreEqual(Status.Ok, result.Result.Summary);

            Assert.AreEqual(3, resultList.Count);
            Assert.AreEqual(2, resultList[0].Index);
            Assert.AreEqual(false, resultList[0].Value);
            Assert.AreEqual(3, resultList[1].Index);
            Assert.AreEqual(true, resultList[1].Value);
            Assert.AreEqual(4, resultList[2].Index);
            Assert.AreEqual(false, resultList[2].Value);

            result = client.ReadDiscreteInputs(param, new AddressRange(9, 2)).Result;
            Assert.AreEqual(Status.Exception, result.Result.Summary);
            Assert.AreEqual(ModbusException.IllegalDataAddress, result.Result.Exception);
        }

        static void TestReadInputRegisters(Channel client)
        {
            var result = client.ReadInputRegisters(param, new AddressRange(3, 3)).Result;
            var resultList = result.Iterator.ToList();
            Assert.AreEqual(Status.Ok, result.Result.Summary);

            Assert.AreEqual(3, resultList.Count);
            Assert.AreEqual(3, resultList[0].Index);
            Assert.AreEqual(0, resultList[0].Value);
            Assert.AreEqual(4, resultList[1].Index);
            Assert.AreEqual(42, resultList[1].Value);
            Assert.AreEqual(5, resultList[2].Index);
            Assert.AreEqual(0, resultList[2].Value);

            result = client.ReadInputRegisters(param, new AddressRange(10, 1)).Result;
            Assert.AreEqual(Status.Exception, result.Result.Summary);
            Assert.AreEqual(ModbusException.IllegalDataAddress, result.Result.Exception);
        }

        static void TestWriteSingleCoil(Channel client)
        {            
            var writeResult = client.WriteSingleCoil(param, new Bit(1, true)).Result;
            Assert.AreEqual(Status.Ok, writeResult.Summary);

            var readResult = client.ReadCoils(param, new AddressRange(0, 2)).Result;
            var resultList = readResult.Iterator.ToList();
            Assert.AreEqual(Status.Ok, readResult.Result.Summary);

            Assert.AreEqual(2, resultList.Count);
            Assert.AreEqual(0, resultList[0].Index);
            Assert.AreEqual(false, resultList[0].Value);
            Assert.AreEqual(1, resultList[1].Index);
            Assert.AreEqual(true, resultList[1].Value);
        }

        static void TestWriteSingleRegister(Channel client)
        {            
            var writeResult = client.WriteSingleRegister(param, new Register(1, 22)).Result;
            Assert.AreEqual(Status.Ok, writeResult.Summary);

            var readResult = client.ReadHoldingRegisters(param, new AddressRange(0, 2)).Result;
            var resultList = readResult.Iterator.ToList();
            Assert.AreEqual(Status.Ok, readResult.Result.Summary);

            Assert.AreEqual(2, resultList.Count);
            Assert.AreEqual(0, resultList[0].Index);
            Assert.AreEqual(0, resultList[0].Value);
            Assert.AreEqual(1, resultList[1].Index);
            Assert.AreEqual(22, resultList[1].Value);
        }

        static void TestWriteMultipeCoils(Channel client)
        {            
            var writeResult = client.WriteMultipleCoils(param, 0, new List<bool> { true, false, true }).Result;
            Assert.AreEqual(Status.Ok, writeResult.Summary);

            var readResult = client.ReadCoils(param, new AddressRange(0, 3)).Result;
            var resultList = readResult.Iterator.ToList();
            Assert.AreEqual(Status.Ok, readResult.Result.Summary);

            Assert.AreEqual(3, resultList.Count);
            Assert.AreEqual(0, resultList[0].Index);
            Assert.AreEqual(true, resultList[0].Value);
            Assert.AreEqual(1, resultList[1].Index);
            Assert.AreEqual(false, resultList[1].Value);
            Assert.AreEqual(2, resultList[2].Index);
            Assert.AreEqual(true, resultList[2].Value);
        }

        static void TestWriteMultipeRegisters(Channel client)
        {
            var writeResult = client.WriteMultipleRegisters(param, 0, new List<ushort> { 0xCAFE, 21, 0xFFFF }).Result;
            Assert.AreEqual(Status.Ok, writeResult.Summary);

            var readResult = client.ReadHoldingRegisters(param, new AddressRange(0, 3)).Result;
            var resultList = readResult.Iterator.ToList();
            Assert.AreEqual(Status.Ok, readResult.Result.Summary);

            Assert.AreEqual(3, resultList.Count);
            Assert.AreEqual(0, resultList[0].Index);
            Assert.AreEqual(0xCAFE, resultList[0].Value);
            Assert.AreEqual(1, resultList[1].Index);
            Assert.AreEqual(21, resultList[1].Value);
            Assert.AreEqual(2, resultList[2].Index);
            Assert.AreEqual(0xFFFF, resultList[2].Value);
        }

        [TestMethod]
        public void ClientAndServerCommunication()
        {
            var runtime = new Runtime(new RuntimeConfig());
            var map = new DeviceMap();
            map.AddEndpoint(UNIT_ID, new WriteHandler(), new DatabaseUpdate((db) =>
            {
                for (ushort i = 0; i < NUM_POINTS; ++i)
                {
                    db.AddCoil(i, false);
                    db.AddDiscreteInput(i, false);
                    db.AddHoldingRegister(i, 0);
                    db.AddInputRegister(i, 0);
                }
            }));

            var server = Server.CreateTcpServer(runtime, ENDPOINT, 100, map, new DecodeLevel());
            var client = Channel.CreateTcpClient(runtime, ENDPOINT, 10, new RetryStrategy(), new DecodeLevel());

            // set a unique pattern to test reads
            server.Update(UNIT_ID, new DatabaseUpdate(db =>
            {
                db.UpdateDiscreteInput(3, true);
                db.UpdateInputRegister(4, 42);
            }));

            TestReadDiscreteInputs(client);
            TestReadInputRegisters(client);
            TestWriteSingleCoil(client);
            TestWriteSingleRegister(client);
            TestWriteMultipeCoils(client);
            TestWriteMultipeRegisters(client);
        }
    }
}
