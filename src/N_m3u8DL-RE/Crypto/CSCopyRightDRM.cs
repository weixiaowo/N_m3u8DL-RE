using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Collections;
namespace CSCopyRightDRM
{
public class CopyRightDRM
{
    private byte[] DecryptionKey = new byte[] { };
    private MemoryStream? FileRead;
    private BinaryReader? FileReader;
    private MemoryStream? FileWrite;
    private BinaryWriter? FileWriter;
    private int PID_1 = -1;
    private byte[] PID_1_BUFFER = new byte[] { };
    private List<string> PID_1_OFFSET = new List<string>();
    private byte[] PID_1_PES_PAYLOAD = new byte[] { };
    private int PID_2 = -1;
    private byte[] PID_2_BUFFER = new byte[] { };
    private List<string> PID_2_OFFSET = new List<string>();
    private byte[] PID_2_PES_PAYLOAD = new byte[] { };
    private readonly int TS_PACKET_SIZE = 188;

    public byte[] DecryptTS(byte[] InputStream, byte[] Key)
    {
        try
        {
            DecryptionKey = Key;
            long InputFileSize = InputStream.Length;
            FileRead = new MemoryStream(InputStream);
            FileReader = new BinaryReader(FileRead);
            FileWrite = new MemoryStream();
            FileWriter = new BinaryWriter(FileWrite);

            do
            {
                int _loc_1 = TS_PACKET_SIZE - 4;
                byte[] PACKET_HEADER = FileReader.ReadBytes(4);

                if (PACKET_HEADER[0] == 0x47)
                {
                    BitArray PACKET_HEADER_BIT = new BitArray(PACKET_HEADER);
                    int PACKET_PID = (PACKET_HEADER[1] & 0x1F) << 8 | PACKET_HEADER[2];

                    bool _loc_3 = false;
                    bool _loc_4 = false;

                    if (PACKET_HEADER_BIT[14] && (PACKET_PID >= 32) && (PACKET_PID <= 1024))
                    {
                        _loc_3 = true;
                        _loc_4 = true;

                        if (PID_1 < 0)
                        {
                            PID_1 = PACKET_PID;
                        }
                        else if (PID_2 < 0 && !(PACKET_PID == PID_1))
                        {
                            PID_2 = PACKET_PID;
                        }
                    }
                    else
                    {
                        if (PACKET_PID == PID_1 || PACKET_PID == PID_2)
                        {
                            _loc_3 = true;
                        }
                    }

                    if (_loc_3)
                    {
                        byte[] PACKET_DATA = new byte[TS_PACKET_SIZE];
                        Array.Copy(PACKET_HEADER, 0, PACKET_DATA, 0, PACKET_HEADER.Length);

                        if (PACKET_HEADER_BIT[29])
                        {
                            byte[] _loc_5 = FileReader.ReadBytes(1);
                            PACKET_DATA[TS_PACKET_SIZE - _loc_1] = _loc_5[0];
                            _loc_1 -= 1;

                            int _loc_6 = (int)_loc_5[0];
                            if (_loc_6 > 0)
                            {
                                _loc_5 = FileReader.ReadBytes(_loc_6);
                                Array.Copy(_loc_5, 0, PACKET_DATA, TS_PACKET_SIZE - _loc_1, _loc_5.Length);
                                _loc_1 -= _loc_6;
                            }
                        }

                        int Offset = TS_PACKET_SIZE - _loc_1;
                        byte[] PES_DATA = FileReader.ReadBytes(_loc_1);
                        Array.Copy(PES_DATA, 0, PACKET_DATA, Offset, PES_DATA.Length);

                        if (_loc_4)
                        {
                            int _loc_7 = 9 + (int)PES_DATA[8];
                            byte[] _loc_8 = new byte[PES_DATA.Length - _loc_7];
                            Array.Copy(PES_DATA, _loc_7, _loc_8, 0, PES_DATA.Length - _loc_7);
                            Offset += _loc_7;
                            PES_DATA = _loc_8;
                        }

                        if (PACKET_PID == PID_1)
                        {
                            if (_loc_4) FlushData("PID_1");
                            PID_1_OFFSET.Add(Offset.ToString());
                            PID_1_BUFFER = AppendTo(PACKET_DATA, PID_1_BUFFER);
                            PID_1_PES_PAYLOAD = AppendTo(PES_DATA, PID_1_PES_PAYLOAD);
                        }
                        else if (PACKET_PID == PID_2)
                        {
                            if (_loc_4) FlushData("PID_2");
                            PID_2_OFFSET.Add(Offset.ToString());
                            PID_2_BUFFER = AppendTo(PACKET_DATA, PID_2_BUFFER);
                            PID_2_PES_PAYLOAD = AppendTo(PES_DATA, PID_2_PES_PAYLOAD);
                        }
                    }
                    else
                    {
                        FileWriter.Write(PACKET_HEADER);
                        FileWriter.Write(FileReader.ReadBytes(_loc_1));
                    }
                }
            } while (FileReader.BaseStream.Position < InputFileSize - 1);

            FlushData("PID_1");
            FlushData("PID_2");

            return FileWrite.ToArray();
        }
        catch (Exception ex)
        {
            return InputStream;
        }
    }

    private void FlushData(string PID)
    {
        try
        {
            if (PID == "PID_1" && PID_1_BUFFER.Length > 0 && FileWriter !=null)
            {
                byte[] _loc_1 = DecryptES(PID_1_PES_PAYLOAD, DecryptionKey);
                int _loc_2 = 0;
                int _loc_3 = 0;

                foreach (string _loc_4 in PID_1_OFFSET)
                {
                    byte[] _loc_5 = new byte[TS_PACKET_SIZE];
                    Array.Copy(PID_1_BUFFER, _loc_2, _loc_5, 0, Convert.ToInt64(_loc_4));
                    _loc_2 += TS_PACKET_SIZE;
                    Array.Copy(_loc_1, _loc_3, _loc_5, Convert.ToInt64(_loc_4), TS_PACKET_SIZE - Convert.ToInt64(_loc_4));
                    _loc_3 += TS_PACKET_SIZE - int.Parse(_loc_4);
                    FileWriter.Write(_loc_5);
                }

                PID_1_BUFFER = new byte[] { };
                PID_1_OFFSET.Clear();
                PID_1_PES_PAYLOAD = new byte[] { };
            }
            else if (PID == "PID_2" && PID_2_BUFFER.Length > 0 && FileWriter !=null)
            {
                byte[] _loc_1 = DecryptES(PID_2_PES_PAYLOAD, DecryptionKey);
                int _loc_2 = 0;
                int _loc_3 = 0;

                foreach (string _loc_4 in PID_2_OFFSET)
                {
                    byte[] _loc_5 = new byte[TS_PACKET_SIZE];
                    Array.Copy(PID_2_BUFFER, _loc_2, _loc_5, 0, Convert.ToInt64(_loc_4));
                    _loc_2 += TS_PACKET_SIZE;
                    Array.Copy(_loc_1, _loc_3, _loc_5, Convert.ToInt64(_loc_4), TS_PACKET_SIZE - Convert.ToInt64(_loc_4));
                    _loc_3 += TS_PACKET_SIZE - int.Parse(_loc_4);
                    FileWriter.Write(_loc_5);
                }

                PID_2_BUFFER = new byte[] { };
                PID_2_OFFSET.Clear();
                PID_2_PES_PAYLOAD = new byte[] { };
            }
        }
        catch  (Exception ex)
        {
            
        }
    }

    private byte[] DecryptES(byte[] InputStream, byte[] Key)
    {
        Aes _loc_1 = Aes.Create();
        _loc_1.BlockSize = 128;
        _loc_1.KeySize = 128;
        _loc_1.Key = Key;
        _loc_1.IV = Key;
        _loc_1.Mode = CipherMode.ECB;
        _loc_1.Padding = PaddingMode.None;

        ICryptoTransform _loc_2 = _loc_1.CreateDecryptor();
        int _loc_3 = InputStream.Length - (InputStream.Length % 16);
        byte[] _loc_4 = _loc_2.TransformFinalBlock(InputStream, 0, _loc_3);

        Array.Copy(_loc_4, InputStream, _loc_4.Length);
        return InputStream;
    }

    public static byte[] HexToBytes(string param1)
    {
        return Enumerable.Range(0, param1.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(param1.Substring(x, 2), 16))
            .ToArray();
    }

    public static string BytesToHex(byte[] param1)
    {
        return BitConverter.ToString(param1).Replace("-", "").ToUpper();
    }

    public static string BytesToBin(byte[] param1)
    {
        StringBuilder _loc_1 = new StringBuilder();
        foreach (byte _loc_2 in param1)
        {
            _loc_1.Append(Convert.ToString(_loc_2, 2).PadLeft(8, '0'));
        }
        return _loc_1.ToString();
    }

    public static byte[] BinToBytes(string param1)
    {
        int _loc_1 = param1.Length / 8;
        byte[] _loc_2 = new byte[_loc_1];

        for (int _loc_3 = 0; _loc_3 < _loc_1; _loc_3++)
        {
            _loc_2[_loc_3] = Convert.ToByte(param1.Substring(8 * _loc_3, 8), 2);
        }

        return _loc_2;
    }

    private byte[] AppendTo(byte[] param1, byte[] param2)
    {
        byte[] _loc_1 = new byte[param1.Length + param2.Length];

        if (param2.Length > 0)
        {
            Array.Copy(param2, _loc_1, param2.Length);
        }

        Array.Copy(param1, 0, _loc_1, param2.Length, param1.Length);
        return _loc_1;
    }
}}