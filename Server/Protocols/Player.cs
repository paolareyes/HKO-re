﻿using System;
using System.IO;
using System.Linq;
using System.Text;
using Extractor;

namespace Server.Protocols {
    class Player {
        public static void Handle(Client client) {
            var req = client.Reader;
            var res = client.Stream;
            var account = client.Account;

            switch(req.ReadByte()) {
                case 0x01: // 005defa2
                    EnterGame(client);
                    break;
                case 0x02: // 005df036 // sent after map load
                    break;
                case 0x04: // 005df0cb
                    OnPlayerMove(client);
                    break;
                case 0x05: // 005df144
                    SetPlayerStatus(client);
                    break;
                case 0x06: // 005df1ca
                    SetPlayerEmote(client);
                    break;
                case 0x07: // 005df240
                    SetPlayerRotation(client);
                    break;
                case 0x08: // 005df2b4
                    SetPlayerState(client);
                    break;
                case 0x0A: // 005df368
                    TakeTeleport(client);
                    break;
                case 0x0B: // 005df415
                    CheckMapHash(req, res);
                    break;
                case 0x0C: // 005df48c
                    EquipItem(client);
                    break;
                case 0x0D: // 005df50c
                    UnEquipItem(client);
                    break;
                /*
                case 0x0E: // 005df580
                case 0x13: // 005df5e2
                */
                case 0x1A: // 005df655 // sent after 02_09
                    Recieve_02_1A(req, res);
                    break;
                // case 0x1f: // 005df6e3
                case 0x20: // 005df763 // change player info
                    SetPlayerInfo(client);
                    break;
                case 0x21: // 005df7d8
                    GetPlayerInfo(client);
                    break;
                /*
                case 0x28: // 005df86e
                case 0x29: // 005df8e4
                case 0x2A: // 005df946
                case 0x2B: // 005df9cb
                case 0x2C: // 005dfa40
                case 0x2D: // 005dfab4
                */
                case 0x32: // 005dfb8c //  client version information
                    Recieve_02_32(req, res);
                    break;
                /*
                case 0x33: // 005dfc04
                case 0x34: // 005dfc78
                case 0x63: // 005dfcee*/

                default:
                    Console.WriteLine("Unknown");
                    break;
            }
        }

        static void ChangeMap(Client client) {
            var map = Program.maps[client.Player.CurrentMap];

            SendChangeMap(client);

            SendNpcs(client.Stream, map.Npcs);
            SendTeleporters(client.Stream, map.Teleporters);
            SendRes(client.Stream, map.Resources);

            var others = Program.clients.Where(other =>
                other != client && other.InGame &&
                other.Player.CurrentMap == client.Player.CurrentMap
            ).ToArray();

            SendAddPlayers(client.Stream, others);

            var packet = BuildAddPlayers(new[] { client });
            foreach(var other in others) {
                packet.Send(other.Stream);
            }
        }

        #region Request
        // 02_01
        static void EnterGame(Client client) {
            client.ReadByte(); // idk

            Login.SendTimoutVal(client.Stream);
            SendPlayerData(client);
            SendPlayerHpSta(client);

            client.InGame = true;
            ChangeMap(client);
        }

        // 02_04
        static void OnPlayerMove(Client client) {
            // player walking
            var mapId = client.ReadInt32(); // mapId
            var x = client.ReadInt32(); // x
            var y = client.ReadInt32(); // y

            var player = client.Player;

            // cancel player action like harvesting
            player.cancelSource?.Cancel();
            player.cancelSource = null;

            player.PositionX = x;
            player.PositionY = y;

            var packet = BuildMovePlayer(client);
            foreach(var other in Program.clients) {
                if(other != client && other.InGame) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_05
        static void SetPlayerStatus(Client client) {
            var data = client.ReadByte();
            // 0 = close

            client.Player.Status = data;

            var packet = BuildPlayerStatus(client);
            foreach(var other in Program.clients) {
                if(other != client && other.InGame && other.Player.CurrentMap == client.Player.CurrentMap) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_06
        static void SetPlayerEmote(Client client) {
            var emote = client.ReadInt32();
            // 1 = blink
            // 2 = yay
            // ...
            // 26 = wave

            var packet = BuildPlayerEmote(client, emote);
            foreach(var other in Program.clients) {
                if(other.InGame && other.Player.CurrentMap == client.Player.CurrentMap) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_07
        static void SetPlayerRotation(Client client) {
            var rotation = client.ReadInt16();
            // 1 = north
            // 2 = north east
            // 3 = east
            // 4 = south east
            // 5 = south
            // 6 = south west
            // 7 = west
            // 8 = north west

            client.Player.Rotation = (byte)rotation;

            var packet = BuildRotatePlayer(client);
            foreach(var other in Program.clients) {
                if(other != client && other.InGame && other.Player.CurrentMap == client.Player.CurrentMap) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_08
        static void SetPlayerState(Client client) {
            var state = client.ReadInt16();
            // 1 = standing
            // 3 = sitting
            // 4 = gathering

            client.Player.State = (byte)state;

            var packet = BuildPlayerState(client);
            foreach(var other in Program.clients) {
                if(other != client && other.InGame && other.Player.CurrentMap == client.Player.CurrentMap) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_0A
        static void TakeTeleport(Client client) {
            var tpId = client.ReadInt16();
            var idk = client.ReadByte(); // always 1?

            var player = client.Player;

            var tp = Program.teleporters[tpId];

            player.CurrentMap = tp.toMap;
            player.PositionX = tp.toX;
            player.PositionY = tp.toY;

            ChangeMap(client);

            // delete players from old map
            var packet = BuildDeletePlayer(client);
            foreach(var other in Program.clients) {
                if(other != client && other.InGame && other.Player.CurrentMap == tp.FromMap) {
                    packet.Send(other.Stream);
                }
            }
        }

        // 02_0B
        static void CheckMapHash(BinaryReader req, Stream res) {
            var mapId = req.ReadInt32();
            var hashHex = req.ReadBytes(32);
        }

        // 02_0C
        static void EquipItem(Client client) {
            var inventorySlot = client.ReadByte();

            var player = client.Player;

            var item = player.Inventory[inventorySlot - 1];
            var att = Program.items[item.Id];

            if(att.Type != (int)ItemType.EQUIPMENT)
                return;

            var equ = Program.equipment[att.SubId];

            if(equ.Gender != 0 && equ.Gender != player.Gender)
                return;

            var type = (byte)equ.Type;

            if(type <= 0 || type >= 14)
                return;

            var equipped = player.Equipment[type - 1];

            // swap currently equipped item to inventory
            player.Inventory[inventorySlot - 1] = equipped;
            Inventory.SendSetItem(client.Stream, equipped, inventorySlot);

            // equip item
            player.Equipment[type - 1] = item;
            SendSetEquItem(client.Stream, item, type);

            int slot = equ.GetEntSlot();

            if(item.Id == 0) {
                player.DisplayEntities[slot] = player.BaseEntities[slot];
            } else {
                player.DisplayEntities[slot] = item.Id;
            }
            SendPlayerAtt(client);
        }

        // 02_0D
        static void UnEquipItem(Client client) {
            var equipSlot = client.ReadByte();

            var player = client.Player;

            var item = player.Equipment[equipSlot - 1];

            int pos = player.AddItem(item.Id, 1);
            if(pos == -1) {
                // todo: no free space
                return;
            }

            player.Equipment[equipSlot - 1] = InventoryItem.Empty;
            SendSetEquItem(client.Stream, InventoryItem.Empty, equipSlot);
            Inventory.SendSetItem(client.Stream, item, (byte)(pos + 1));

            var att = Program.items[item.Id];
            var equ = Program.equipment[att.SubId];

            int slot = equ.GetEntSlot();
            player.DisplayEntities[slot] = player.BaseEntities[slot];
            SendPlayerAtt(client);
        }

        // 02_1A
        static void Recieve_02_1A(BinaryReader req, Stream res) {
            var winmTime = req.ReadInt32();
        }

        // 02_20
        static void SetPlayerInfo(Client client) {
            var data = PacketBuilder.DecodeCrazy(client.Reader); // 970 bytes

            // TODO: null trim
            var birth = Encoding.ASCII.GetString(data, 1, data[0]); // 0 - 37
            var phone = Encoding.ASCII.GetString(data, 39, data[38]); // 38 - 63
            var location = Encoding.Unicode.GetString(data, 64, 36 * 2); // 63 - 135
            var email = Encoding.ASCII.GetString(data, 137, data[136]); // 136 - 201
            var favorite = Encoding.Unicode.GetString(data, 202, 64 * 2); // 202 - 329
            var hobby = Encoding.Unicode.GetString(data, 330, 160 * 2); // 330 - 649
            var intro = Encoding.Unicode.GetString(data, 650, 160 * 2); // 650 - 969
        }

        // 02_21
        static void GetPlayerInfo(Client client) {
            var playerId = client.ReadInt16();
            var player = Program.clients.First(x => x.Id == playerId);

            /*if(player != null) 
                SendPlayerInfo(client, player);*/
        }

        // 02_32
        static void Recieve_02_32(BinaryReader req, Stream res) {
            int count = req.ReadInt32();
            for(int i = 0; i < count; i++) {
                int aLen = req.ReadByte();
                var name = Encoding.ASCII.GetString(req.ReadBytes(aLen));

                int bLen = req.ReadByte();
                var version = Encoding.ASCII.GetString(req.ReadBytes(bLen));

                // Console.WriteLine($"{name} : {version}");
            }

            // Send02_6E(clientStream);
        }
        #endregion

        static void writeFriend(PacketBuilder w) {
            // name - wchar[32]
            for(int i = 0; i < 32; i++)
                w.WriteShort(0);
            w.WriteInt(0); // length
        }
        static void writePetData(PacketBuilder w) {
            for(int i = 0; i < 0xd8; i++)
                w.WriteByte(0);
        }

        #region Response
        // 02_01
        static void SendPlayerData(Client client) {
            var player = client.Player;

            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x1); // second switch

            b.BeginCompress(); // player data - should be 38608 bytes
            b.WriteInt(0); // server token?
            b.WriteByte(0); // char str length
            for(int i = 0; i < 65; i++) {
                b.WriteByte(0);
            }
            // null terminated wchar string
            { // player name
                var bytes = Encoding.Unicode.GetBytes(player.Name);
                b.Write(bytes);
                b.Write0(64 - bytes.Length);
            }

            b.Write0(18); // idk

            b.WriteInt(player.CurrentMap); // mapId
            b.WriteInt(player.PositionX); // x
            b.WriteInt(player.PositionY); // y

            b.WriteByte(player.Rotation);
            b.WriteByte(0);
            b.WriteByte(player.Speed);
            b.WriteByte(player.Gender); // gender

            player.WriteEntities(b);

            b.WriteInt(player.Money); // money

            b.WriteByte(0); // status (0 = online, 1 = busy, 2 = away)
            b.WriteByte(0); // active petId
            b.WriteByte(0); // emotionSomething
            b.WriteByte(0); // unused
            b.WriteByte(player.BloodType); // blood type
            b.WriteByte(player.BirthMonth); // birth month
            b.WriteByte(player.BirthDay); // birth day
            b.WriteByte(player.GetConstellation()); // constellation // todo: calculate this from brithday

            b.WriteInt(0); // guild id?

            for(int i = 0; i < 10; i++)
                b.WriteInt(0); // quick bar

            b.Write0(76); // idk

            for(int i = 0; i < 14; i++)
                b.Write(player.Equipment[i]); // equipment
            for(int i = 0; i < 6; i++)
                b.Write(InventoryItem.Empty); // inv2

            // main inventory
            for(int i = 0; i < 50; i++)
                b.Write(player.Inventory[i]);
            b.WriteByte((byte)player.InventorySize); // size
            b.Write0(3); // unused

            // farm inventory
            for(int i = 0; i < 200; i++)
                b.Write(InventoryItem.Empty);
            b.WriteByte(0); // size
            b.Write0(3); // unused

            for(int i = 0; i < 100; i++)
                writeFriend(b); // friend list
            b.WriteByte(0); // friend count
            b.Write0(3); // unused

            for(int i = 0; i < 50; i++)
                writeFriend(b); // ban list
            b.WriteByte(0); // ban count
            b.Write0(3); // unused

            for(int i = 0; i < 3; i++)
                writePetData(b); // pet data

            b.Write0(1000); // quest flags

            // active quests
            for(int i = 0; i < 10; i++) {
                b.WriteInt(0); // questId
                b.WriteByte(0); // flags1
                b.WriteByte(0); // flags2
                b.Write0(2); // unused
            }

            b.WriteByte(0);
            b.WriteByte(0); // crystals
            b.WriteByte(0);
            b.WriteByte(0);

            b.Write0(2 * 40); // short array
            b.Write0(128); // byte array

            player.WriteLevels(b);

            b.Write0(9 * 64); // 9 * byte[64]

            b.WriteInt(0);

            // TODO: finish figuring out the rest

            b.EndCompress();

            b.Send(client.Stream);
        }

        // 02_02
        static PacketBuilder BuildAddPlayers(Client[] clients) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x2); // second switch

            b.WriteShort((short)clients.Length); // count
            b.BeginCompress();
            foreach(var client in clients) {
                b.WriteShort(client.Id);
                b.WriteByte(0); // status icon
                b.WriteByte(0); // guild icon
                b.WriteByte(0);

                b.Write0(16 * 2); // guild name
                b.WriteInt(0);
                { // player name
                    var bytes = Encoding.Unicode.GetBytes(client.Player.Name);
                    b.Write(bytes);
                    b.Write0(64 - bytes.Length);
                }
                b.Write0(65);

                b.WriteInt(0);
                b.WriteInt(client.Player.PositionX);
                b.WriteInt(client.Player.PositionY);

                b.WriteByte(client.Player.Rotation);
                b.WriteByte(0);
                b.WriteByte(client.Player.Speed); // speed
                b.WriteByte(client.Player.Gender);

                client.Player.WriteEntities(b);

                b.WriteInt(0);
                b.WriteInt(0);

                b.WriteByte(0); // player title
            }
            b.EndCompress();

            return b;
        }
        // 02_02
        static void SendAddPlayers(Stream res, Client[] clients) {
            BuildAddPlayers(clients).Send(res);
        }

        // 02_03
        static PacketBuilder BuildDeletePlayer(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x3); // second switch

            b.WriteShort(client.Id);
            b.WriteShort(0); // unused?

            return b;
        }

        // 02_04
        static PacketBuilder BuildMovePlayer(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x4); // second switch

            b.WriteShort(client.Id);
            b.WriteInt(client.Player.PositionX);
            b.WriteInt(client.Player.PositionY);
            b.WriteShort(client.Player.Speed);

            return b;
        }

        // 02_05
        static PacketBuilder BuildPlayerStatus(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x5); // second switch

            b.WriteShort(client.Id);
            b.WriteInt(client.Player.Status);

            return b;
        }

        // 02_06
        static PacketBuilder BuildPlayerEmote(Client client, int emote) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x6); // second switch

            b.WriteShort(client.Id);
            b.WriteInt(emote);

            return b;
        }

        // 02_07
        static PacketBuilder BuildRotatePlayer(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x7); // second switch

            b.WriteShort(client.Id);
            b.WriteShort(client.Player.Rotation);

            return b;
        }

        // 02_08
        static PacketBuilder BuildPlayerState(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x8); // second switch

            b.WriteShort(client.Id);
            b.WriteShort(client.Player.State);

            return b;
        }

        // 02_09
        static void SendChangeMap(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0x9); // second switch

            var player = client.Player;

            b.WriteInt(player.CurrentMap);
            b.WriteShort((short)player.PositionX);
            b.WriteShort((short)player.PositionY);
            b.WriteByte(0);

            /*if(mapType == 3) {
                b.EncodeCrazy(Array.Empty<byte>());
                b.Add((int)0);
                b.AddString("", 1);
                b.Add((byte)0);
                b.Add((byte)0);
                b.EncodeCrazy(Array.Empty<byte>());
                b.Add((int)0);
            } else if(mapType == 4) {
                b.EncodeCrazy(Array.Empty<byte>());
                b.EncodeCrazy(Array.Empty<byte>());
            }*/

            b.WriteByte(0);
            /*
            if(byte == 99) {
                // have_data
                b.Add((int)0);
                b.AddString("", 2);
            } else {
                // no_data
            }
            */

            b.Send(client.Stream);
        }

        // 02_0C
        static void SendPlayerAtt(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0xC); // second switch

            b.WriteShort(client.Id);

            b.WriteShort(18 * 4); // size
            for(int i = 0; i < 18; i++) {
                b.WriteInt(client.Player.DisplayEntities[i]);
            }

            b.Send(client.Stream);
        }

        // 02_12
        static void SendPlayerHpSta(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x12); // second switch

            b.WriteShort(client.Id); // player id

            var player = client.Player;

            b.BeginCompress();
            b.WriteInt(player.Hp); // hp
            b.WriteInt(player.MaxHp); // hp max
            b.WriteInt(player.Sta); // sta
            b.WriteInt(player.MaxSta); // sta max
            b.EndCompress();

            b.Send(client.Stream);
        }

        // 02_0F
        static void SendTeleportPlayer(Client client) {
            var b = new PacketBuilder();

            b.WriteByte(0x2); // first switch
            b.WriteByte(0xF); // second switch

            var player = client.Player;

            b.WriteShort(client.Id); // player id
            b.WriteInt(player.PositionX); // x
            b.WriteInt(player.PositionY); // y

            b.Send(client.Stream);
        }

        // 02_11
        static void SendSetEquItem(Stream clientStream, InventoryItem item, byte position) {
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x11); // second switch

            b.BeginCompress();
            b.Write(item);
            b.EndCompress();

            b.WriteByte(position); // position
            b.WriteByte(1); // action
            b.WriteByte(0); // play sound

            b.Send(clientStream);
        }

        static void writeTeleport(PacketBuilder w, Teleport tp) {
            w.WriteInt(tp.Id); // id
            w.WriteInt(tp.fromX); // x
            w.WriteInt(tp.fromY); // y
            w.WriteInt(0); // flagId
            w.WriteByte((byte)tp.rotation); // direction
            w.WriteByte(0);
            w.WriteByte(0);
            w.WriteByte(0); // unused
            w.WriteInt(0); // somethingTutorial
            w.WriteInt(0); // roomNum
            w.WriteInt(0); // consumeItem
            w.WriteInt(0); // consumeItemCount
            w.WriteByte(0); // byte idk
            w.WriteByte(0); // unused
            w.WriteShort(0); // stringId
            w.WriteInt(0); // keyItem
        }
        static void SendTeleporters(Stream clientStream, Teleport[] teleporters) {
            // 02_14 and 02_15
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x14); // second switch

            b.WriteInt(teleporters.Length); // count

            b.BeginCompress();
            foreach(var teleporter in teleporters) {
                writeTeleport(b, teleporter);
            }
            b.EndCompress();

            b.Send(clientStream);
        }

        static void writeNpcData(PacketBuilder w, NPCName npc) {
            w.WriteInt(npc.Id); // entity/npc id
            w.WriteInt(npc.X); // x 
            w.WriteInt(npc.Y); // y

            w.WriteByte((byte)npc.Rotation); // rotation
            w.Write0(3); // unused

            w.WriteInt(0);
            w.WriteInt(0);
            w.WriteInt(0);
            w.WriteInt(0);
        }
        // 02_16
        static void SendNpcs(Stream clientStream, NPCName[] npcs) {
            // create npcs
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x16); // second switch

            b.WriteInt(npcs.Length); // count

            b.BeginCompress();
            foreach(var npc in npcs) {
                writeNpcData(b, npc);
            }
            b.EndCompress();

            b.Send(clientStream);
        }

        static void writeResData(PacketBuilder w, Extractor.Resource res) {
            w.WriteInt(res.Id); // entity/npc id
            w.WriteInt(res.X); // x 
            w.WriteInt(res.Y); // y

            w.WriteShort(res.NameId); // nameId
            w.WriteShort(res.Count); // count

            w.WriteByte(1); // rotation
            w.Write0(3); // unused

            w.WriteShort(res.Type1); // type 1 - 0 = gather, 1 = mine, 2 = attack, 3 = ?
            w.WriteShort(res.Type2); // type 2 - 0 = gather, 1 = mine, 2 = attack

            w.WriteByte(0); // 5 = no lan man?
            w.Write0(3); // unused
        }
        // 02_17
        static void SendRes(Stream clientStream, Extractor.Resource[] resources) {
            // create npcs
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x17); // second switch

            b.WriteInt(resources.Length); // count

            b.BeginCompress();
            foreach(var res in resources) {
                writeResData(b, res);
            }
            b.EndCompress();

            b.Send(clientStream);
        }

        // 02_6E
        static void Send02_6E(Stream clientStream) {
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x6E); // second switch

            b.WriteWString("");
            b.WriteInt(8); // map id?
            b.AddString("", 1);

            b.Send(clientStream);
        }

        // 02_6F
        static void Send02_6F(Stream clientStream) {
            var b = new PacketBuilder();

            b.WriteByte(0x02); // first switch
            b.WriteByte(0x6E); // second switch

            b.WriteByte(0);

            b.Send(clientStream);
        }

        #endregion
    }
}