﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using MySql.Data.MySqlClient;

namespace Server {
    class IdManager {
        private static HashSet<int> AvalibleIds = new HashSet<int>();
        private static int MaxId = 0;

        public static int GetId() {
            if(AvalibleIds.Count == 0) {
                return ++MaxId;
            } else {
                int id = AvalibleIds.First();
                AvalibleIds.Remove(id);
                return id;
            }
        }
        public static void FreeId(int id) {
            if(id == MaxId) {
                MaxId--;
            } else {
                AvalibleIds.Add(id);
            }
        }
    }

    public class DictionaryInt32Converter : JsonConverter<Dictionary<int, int>> {
        public override Dictionary<int, int> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
            if(reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException("Expected Object");

            var value = new Dictionary<int, int>();

            while(reader.Read()) {
                if(reader.TokenType == JsonTokenType.EndObject) {
                    return value;
                }

                var keyString = reader.GetString();

                if(!int.TryParse(keyString, out var keyAsInt32)) {
                    throw new JsonException($"Unable to convert \"{keyString}\" to System.Int32.");
                }

                reader.Read();
                value.Add(keyAsInt32, reader.GetInt32());
            }

            throw new JsonException("Error Occurred");
        }

        public override void Write(Utf8JsonWriter writer, Dictionary<int, int> value, JsonSerializerOptions options) {
            writer.WriteStartObject();

            foreach(var (key, val) in value) {
                writer.WriteNumber(key.ToString(), val);
            }

            writer.WriteEndObject();
        }
    }

    enum LoginResponse {
        Ok,
        NoUser,
        InvalidPassword,
        AlreadyOnline
    }

    static class Database {
        private static HashSet<string> _online = new HashSet<string>();
        private static string _connectionString;

        public static void SetConnectionString(string str) {
            _connectionString = str;
        }

        public static LoginResponse Login(string username, string password, out PlayerData playerData) {
            if(_online.Contains(username)) {
                playerData = null;
                return LoginResponse.AlreadyOnline;
            }

            var connection = new MySqlConnection(_connectionString);
            connection.Open();

            LogRequest("select * from account where username = @name");

            var command = connection.CreateCommand();
            command.CommandText = "select * from account where username = @name";
            command.Parameters.AddWithValue("name", username);

            var reader = command.ExecuteReader(CommandBehavior.SingleRow);

            if(!reader.Read()) {
                playerData = null;
                return LoginResponse.NoUser;
            }

            var buff = new byte[48];

            reader.GetBytes("password", 0, buff, 0, 48);

            if(!VerifyPassword(password, buff)) {
                playerData = null;
                return LoginResponse.InvalidPassword;
            }

            if (!reader.IsDBNull("data")) {
                var data = reader.GetString("data");
                playerData = JsonSerializer.Deserialize<PlayerData>(data, new JsonSerializerOptions {
                    Converters = { new DictionaryInt32Converter() }
                });
                playerData.Init();
            } else {
                playerData = null;
            }

            _online.Add(username);
            return LoginResponse.Ok;
        }

        public static void LogOut(string username, PlayerData data) {
            var connection = new MySqlConnection(_connectionString);
            connection.Open();

            LogRequest("update account set data = @data where username = @name");

            var command = connection.CreateCommand();
            command.CommandText = "update account set data = @data where username = @name";
            command.Parameters.AddWithValue("name", username);

            if(data == null) {
                command.Parameters.AddWithValue("data", null);
            } else {
                command.Parameters.AddWithValue("data", JsonSerializer.Serialize(data, new JsonSerializerOptions {
                    Converters = { new DictionaryInt32Converter() }
                }));
            }

            command.ExecuteNonQuery();

            _online.Remove(username);
        }

        private static void LogRequest(string query) {
            var logger = Program.loggerFactory.CreateLogger("Database");
            logger.LogInformation($"Executing Query \"{query}\"");
        }

        private static byte[] GenerateSalt() {
            byte[] salt = new byte[128 / 8];
            var rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetNonZeroBytes(salt);
            return salt;
        }

        private static byte[] HashPassword(byte[] salt, string password) {
            var rfc = new Rfc2898DeriveBytes(password, salt, 10000);
            return rfc.GetBytes(256 / 8);
        }

        private static bool VerifyPassword(string password, byte[] account) {
            var hash = HashPassword(account[..16], password);
            return hash.SequenceEqual(account[16..]);
        }
    }
}