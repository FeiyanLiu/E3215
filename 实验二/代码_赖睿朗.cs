using System;
using System.IO.Ports;
using System.Threading;

public class PortChat
{
    static bool _continue;
    static SerialPort _serialPort;


    public static void Main()
    {
        string message;
        StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
        Thread readThread = new Thread(Read);

        // Create a new SerialPort object with default settings.
        _serialPort = new SerialPort();

        // Allow the user to set the appropriate properties.
        _serialPort.PortName = SetPortName(_serialPort.PortName);
        _serialPort.BaudRate = SetPortBaudRate(_serialPort.BaudRate);
        _serialPort.Parity = SetPortParity(_serialPort.Parity);
        _serialPort.DataBits = SetPortDataBits(_serialPort.DataBits);
        _serialPort.StopBits = SetPortStopBits(_serialPort.StopBits);
        _serialPort.Handshake = SetPortHandshake(_serialPort.Handshake);

        // Set the read/write timeouts
        _serialPort.ReadTimeout = 500;
        _serialPort.WriteTimeout = 500;

        _serialPort.Open();
        _continue = true;
        readThread.Start();


        Console.WriteLine("开始通信，输入\"exit\"退出");
        Random s = new Random();
        while (_continue)
        {
            message = Console.ReadLine();
            Console.WriteLine(String.Format("{0}: {1}", get_sent_time(), message));
            if (message == "rand")
            {
                for (int i = 0; i < 30000; i++)
                    message += s.Next().ToString();
            }

            if (stringComparer.Equals("exit", message))
            {
                _continue = false;
            }
            else
            {
                if (message[0] == 'r')
                    message = "rand";
                _serialPort.WriteLine(String.Format("{0}: {1}", get_rec_time(), message));
            }
        }

        readThread.Join();
        _serialPort.Close();
    }

    public static string get_sent_time()
    {
        return "[SENT " + DateTime.Now.ToString() + "]";
    }
    public static string get_rec_time()
    {
        return "[RECV " + DateTime.Now.ToString() + "]";
    }

    public static void Read()
    {
        while (_continue)
        {
            try
            {
                string message = _serialPort.ReadLine();
                Console.WriteLine(message);
            }
            catch (TimeoutException) { }
        }
    }

    public static string SetPortName(string defaultPortName)
    {
        string portName;

        Console.WriteLine("可用通道：");
        foreach (string s in SerialPort.GetPortNames())
        {
            Console.WriteLine("   {0}", s);
        }

        Console.Write("输入使用的通道名（默认值: {0}）: ", defaultPortName);
        portName = Console.ReadLine();

        if (portName == "" || !(portName.ToLower()).StartsWith("com"))
        {
            portName = defaultPortName;
        }
        return portName;
    }
    public static int SetPortBaudRate(int defaultPortBaudRate)
    {
        string baudRate;

        Console.Write("请输入比特率（默认值：{0}）： ", defaultPortBaudRate);
        baudRate = Console.ReadLine();

        if (baudRate == "")
        {
            baudRate = defaultPortBaudRate.ToString();
        }

        return int.Parse(baudRate);
    }

    public static Parity SetPortParity(Parity defaultPortParity)
    {
        string parity;
        parity = defaultPortParity.ToString();
        return (Parity)Enum.Parse(typeof(Parity), parity, true);
    }
    public static int SetPortDataBits(int defaultPortDataBits)
    {
        string dataBits;

        dataBits = defaultPortDataBits.ToString();

        return int.Parse(dataBits.ToUpperInvariant());
    }

    public static StopBits SetPortStopBits(StopBits defaultPortStopBits)
    {
        string stopBits;

        Console.WriteLine("可选停止位数选项：");
        int tot = 1;
        foreach (string s in Enum.GetNames(typeof(StopBits)))
        {
            //if (s == 0) continue;
            Console.WriteLine("{0}：   {1}", tot++, s);
        }

        Console.Write("请选择停止位数：", defaultPortStopBits.ToString());
        stopBits = Console.ReadLine();

        if (stopBits == "")
        {
            stopBits = defaultPortStopBits.ToString();
        }

        return (StopBits)Enum.Parse(typeof(StopBits), stopBits, true);
    }
    public static Handshake SetPortHandshake(Handshake defaultPortHandshake)
    {
        string handshake;

        handshake = defaultPortHandshake.ToString();

        return (Handshake)Enum.Parse(typeof(Handshake), handshake, true);
    }
}