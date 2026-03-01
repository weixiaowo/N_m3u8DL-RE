using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Buffers;
using System.Collections; // BitArray所需命名空间

// 核心修复1：类名改为Bbts（匹配文件名和SimpleDownloader的引用）
namespace CSBBTS
{
public class BBTS
{
    // 核心修复2：添加?标记为可空类型，解决CS8618警告
    private byte[] BlockDecryptionKey = new byte[0];
    private byte[] DecryptionKey = new byte[0];
    private MemoryStream? FileRead;          // 可空标记
    private BinaryReader? FileReader;        // 可空标记
    private MemoryStream? FileWrite;         // 可空标记
    private BinaryWriter? FileWriter;        // 可空标记
    private int PID_1 = -1;
    private byte[] PID_1_BUFFER = new byte[0];
    private List<string> PID_1_OFFSET = new List<string>();
    private byte[] PID_1_PES_PAYLOAD = new byte[0];
    private int PID_2 = -1;
    private byte[] PID_2_BUFFER = new byte[0];
    private List<string> PID_2_OFFSET = new List<string>();
    private byte[] PID_2_PES_PAYLOAD = new byte[0];
    private readonly int TS_PACKET_SIZE = 188;

    // 解密核心方法（逻辑不变，仅补充空值校验）
    public byte[] DecryptTS(byte[] InputStream, byte[] Key)
    {
        try
        {
            DecryptionKey=Key;
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

                    // 解析SDT包获取块解密密钥
                    if (PACKET_PID == 17)
                    {
                        byte[] SDT_PAYLOAD = FileReader.ReadBytes(_loc_1);
                        FileReader.BaseStream.Position -= _loc_1;
                        StringBuilder _loc_11 = new StringBuilder();
                        foreach (byte _loc_12 in SDT_PAYLOAD)
                        {
                            if (_loc_12 >= 32 && _loc_12 <= 126)
                                _loc_11.Append((char)_loc_12);
                        }
                        MatchCollection _loc_13 = Regex.Matches(_loc_11.ToString(), @"\|v([0-9a-fA-F]{32})\|");
                        if (_loc_13.Count > 0)
                            BlockDecryptionKey = HexToBytes(_loc_13[0].Groups[1].Value);
                    }

                    bool _loc_3 = false;
                    bool _loc_4 = false;

                    // 判断是否为目标PID包
                    if (PACKET_HEADER_BIT[14] && PACKET_PID >= 32 && PACKET_PID <= 256)
                    {
                        _loc_3 = true;
                        _loc_4 = true;
                        if (PID_1 < 0)
                        {
                            PID_1 = PACKET_PID;
                        }
                        else if (PID_2 < 0 && PACKET_PID != PID_1)
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

                        // 处理适配字段
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

                        // 处理PES负载
                        if (_loc_4)
                        {
                            int _loc_7 = 9 + (int)PES_DATA[8];
                            byte[] _loc_8 = new byte[PES_DATA.Length - _loc_7];
                            Array.Copy(PES_DATA, _loc_7, _loc_8, 0, PES_DATA.Length - _loc_7);
                            Offset += _loc_7;
                            PES_DATA = _loc_8;
                        }

                        if (BlockDecryptionKey.Length != 16)
                            return InputStream;

                        // 缓存PID1数据
                        if (PACKET_PID == PID_1)
                        {
                            if (_loc_4)
                                FlushData("PID_1");
                            PID_1_OFFSET.Add(Offset.ToString());
                            PID_1_BUFFER = AppendTo(PACKET_DATA, PID_1_BUFFER);
                            PID_1_PES_PAYLOAD = AppendTo(PES_DATA, PID_1_PES_PAYLOAD);
                        }
                        // 缓存PID2数据
                        else if (PACKET_PID == PID_2)
                        {
                            if (_loc_4)
                                FlushData("PID_2");
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
            } while (!(FileReader.BaseStream.Position >= InputFileSize - 1));

            // 刷新剩余缓存数据
            FlushData("PID_1");
            FlushData("PID_2");

            return FileWrite.ToArray();
        }
        catch (Exception ex)
        {
            // 异常时返回原始数据
            Console.WriteLine($"解密过程异常: {ex.Message}");
            return InputStream;
        }
    }

    private void FlushData(string PID)
    {
        try
        {
            // 处理PID1缓存数据（补充FileWriter空值校验）
            if (PID == "PID_1" && PID_1_BUFFER.Length > 0 && FileWriter != null)
            {
                byte[] _loc_1 = DecryptES(PID_1_PES_PAYLOAD, DecryptionKey, BlockDecryptionKey);
                int _loc_2 = 0;
                int _loc_3 = 0;

                foreach (string _loc_4 in PID_1_OFFSET)
                {
                    byte[] _loc_5 = new byte[TS_PACKET_SIZE];
                    Array.Copy(PID_1_BUFFER, _loc_2, _loc_5, 0, Convert.ToInt64(_loc_4));
                    _loc_2 += TS_PACKET_SIZE;
                    Array.Copy(_loc_1, _loc_3, _loc_5, Convert.ToInt64(_loc_4), TS_PACKET_SIZE - Convert.ToInt64(_loc_4));
                    _loc_3 += TS_PACKET_SIZE - Convert.ToInt32(_loc_4);
                    FileWriter.Write(_loc_5);
                }

                // 清空缓存
                PID_1_BUFFER = new byte[0];
                PID_1_OFFSET.Clear();
                PID_1_PES_PAYLOAD = new byte[0];
            }
            // 处理PID2缓存数据（补充FileWriter空值校验）
            else if (PID == "PID_2" && PID_2_BUFFER.Length > 0 && FileWriter != null)
            {
                byte[] _loc_1 = DecryptES(PID_2_PES_PAYLOAD, DecryptionKey, BlockDecryptionKey);
                int _loc_2 = 0;
                int _loc_3 = 0;

                foreach (string _loc_4 in PID_2_OFFSET)
                {
                    byte[] _loc_5 = new byte[TS_PACKET_SIZE];
                    Array.Copy(PID_2_BUFFER, _loc_2, _loc_5, 0, Convert.ToInt64(_loc_4));
                    _loc_2 += TS_PACKET_SIZE;
                    Array.Copy(_loc_1, _loc_3, _loc_5, Convert.ToInt64(_loc_4), TS_PACKET_SIZE - Convert.ToInt64(_loc_4));
                    _loc_3 += TS_PACKET_SIZE - Convert.ToInt32(_loc_4);
                    FileWriter.Write(_loc_5);
                }

                // 清空缓存
                PID_2_BUFFER = new byte[0];
                PID_2_OFFSET.Clear();
                PID_2_PES_PAYLOAD = new byte[0];
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FlushData异常: {ex.Message}");
        }
    }

    public byte[] DecryptES(byte[] InputStream, byte[] Key, byte[] BlockKey)
    {
        // 核心修复3：替换过时的Aes.Create("AES")为无参构造，补充空值校验
        Aes? _loc_1 = Aes.Create(); // 无参构造（解决SYSLIB0045警告）
        if (_loc_1 == null)
        {
            throw new InvalidOperationException("无法创建AES加密算法实例");
        }

        _loc_1.BlockSize = 128;
        _loc_1.Key = Key;
        _loc_1.Mode = CipherMode.ECB;
        _loc_1.Padding = PaddingMode.None;

        byte[] _loc_2 = new byte[InputStream.Length];
        Array.Copy(InputStream, _loc_2, InputStream.Length);

        int _loc_3 = -1;
        int _loc_4 = 0;

        // 查找NALU边界并解密
        while (_loc_4 <= _loc_2.Length - 4)
        {
            // 查找4字节NALU起始码 (00 00 00 01)
            if (_loc_2[_loc_4] == 0 && _loc_2[_loc_4 + 1] == 0 && _loc_2[_loc_4 + 2] == 0 && _loc_2[_loc_4 + 3] == 1)
            {
                if (_loc_3 != -1)
                {
                    int _loc_5 = _loc_4 - _loc_3;
                    byte[] _loc_6 = new byte[_loc_5];
                    Array.Copy(_loc_2, _loc_3, _loc_6, 0, _loc_5);
                    byte[] _loc_7 = DecryptNAL(_loc_6, BlockKey, _loc_1);
                    Array.Copy(_loc_7, 0, _loc_2, _loc_3, _loc_5);
                }
                _loc_3 = _loc_4;
                _loc_4 += 4;
            }
            // 查找3字节NALU起始码 (00 00 01)
            else if (_loc_2[_loc_4] == 0 && _loc_2[_loc_4 + 1] == 0 && _loc_2[_loc_4 + 2] == 1)
            {
                if (_loc_3 != -1)
                {
                    int _loc_5 = _loc_4 - _loc_3;
                    byte[] _loc_6 = new byte[_loc_5];
                    Array.Copy(_loc_2, _loc_3, _loc_6, 0, _loc_5);
                    byte[] _loc_7 = DecryptNAL(_loc_6, BlockKey, _loc_1);
                    Array.Copy(_loc_7, 0, _loc_2, _loc_3, _loc_5);
                }
                _loc_3 = _loc_4;
                _loc_4 += 3;
            }
            else
            {
                _loc_4 += 1;
            }
        }

        // 处理最后一个NALU
        if (_loc_3 != -1 && _loc_3 < _loc_2.Length)
        {
            int _loc_5 = _loc_2.Length - _loc_3;
            byte[] _loc_6 = new byte[_loc_5];
            Array.Copy(_loc_2, _loc_3, _loc_6, 0, _loc_5);
            byte[] _loc_7 = DecryptNAL(_loc_6, BlockKey, _loc_1);
            Array.Copy(_loc_7, 0, _loc_2, _loc_3, _loc_5);
        }

        return _loc_2;
    }

    public byte[] DecryptNAL(byte[] InputStream, byte[] BlockKey, Aes AesHandle)
    {
        byte[] _loc_11 = new byte[InputStream.Length];
        Array.Copy(InputStream, _loc_11, InputStream.Length);

        byte[] _loc_9 = new byte[_loc_11.Length];
        int _loc_22 = 0;
        int _loc_23 = 0;

        // 处理NALU数据中的特殊字节
        while (_loc_22 < _loc_11.Length)
        {
            if (_loc_22 + 3 < _loc_11.Length && _loc_11[_loc_22] == 0x0 && _loc_11[_loc_22 + 1] == 0x0 && 
                _loc_11[_loc_22 + 2] == 0x3 && (_loc_11[_loc_22 + 3] == 0x0 || _loc_11[_loc_22 + 3] == 0x1 || 
                _loc_11[_loc_22 + 3] == 0x2 || _loc_11[_loc_22 + 3] == 0x3))
            {
                _loc_9[_loc_23] = _loc_11[_loc_22]; _loc_23++;
                _loc_9[_loc_23] = _loc_11[_loc_22 + 1]; _loc_23++;
                _loc_9[_loc_23] = _loc_11[_loc_22 + 3]; _loc_23++;
                _loc_22 += 4;
            }
            else
            {
                _loc_9[_loc_23] = _loc_11[_loc_22];
                _loc_22++;
                _loc_23++;
            }
        }

        // 提取需要解密的核心数据
        byte[] _loc_12 = new byte[_loc_23 - 5 - 2];
        Array.Copy(_loc_9, 5, _loc_12, 0, _loc_12.Length);

        // 分块解密（16字节为一块）
        int _loc_13 = (int)Math.Ceiling((double)_loc_12.Length / 16);
        int _loc_14 = 0;

        for (int _loc_15 = 1; _loc_15 <= _loc_13; _loc_15++)
        {
            byte[] _loc_16 = BitConverter.GetBytes(_loc_15);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(_loc_16);

            // 构造加密向量：BlockKey前12字节 + 块序号
            byte[] _loc_17 = BlockKey.Take(12).Concat(_loc_16).ToArray();

            // 每10块的第一个块或最后一个块需要AES加密处理
            if (_loc_15 % 10 == 1 || _loc_15 == _loc_13)
                _loc_17 = AesHandle.CreateEncryptor().TransformFinalBlock(_loc_17, 0, _loc_17.Length);

            // XOR解密
            for (int _loc_18 = 0; _loc_18 < _loc_17.Length; _loc_18++)
            {
                _loc_12[_loc_14] = (byte)(_loc_12[_loc_14] ^ _loc_17[_loc_18]);
                _loc_14++;
                if (_loc_14 == _loc_12.Length)
                    break;
            }
        }

        // 将解密后的数据写回
        Array.Copy(_loc_12, 0, _loc_11, 5, _loc_12.Length);
        Array.Copy(_loc_9, 5 + _loc_12.Length, _loc_11, 5 + _loc_12.Length, 2);

        // 清空剩余字节
        int _loc_10 = _loc_11.Length - 5 - _loc_12.Length - 2;
        if (_loc_10 > 0)
        {
            for (int _loc_19 = 1; _loc_19 <= _loc_10; _loc_19++)
            {
                _loc_11[_loc_11.Length - _loc_10] = 0;
            }
        }

        return _loc_11;
    }

    // 16进制字符串转字节数组
    public static byte[] HexToBytes(string param1)
    {
        return Enumerable.Range(0, param1.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(param1.Substring(x, 2), 16))
            .ToArray();
    }

    // 字节数组转16进制字符串
    public static string BytesToHex(byte[] param1)
    {
        return BitConverter.ToString(param1).Replace("-", "").ToUpper();
    }

    // 字节数组转二进制字符串
    public static string BytesToBin(byte[] param1)
    {
        StringBuilder _loc_1 = new StringBuilder();
        foreach (byte _loc_2 in param1)
        {
            _loc_1.Append(Convert.ToString(_loc_2, 2).PadLeft(8, '0'));
        }
        return _loc_1.ToString();
    }

    // 二进制字符串转字节数组
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

    // 拼接两个字节数组
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
