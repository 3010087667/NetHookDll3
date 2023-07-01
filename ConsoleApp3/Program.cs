using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using EasyHook;

namespace HookDLL
{
    public class HookEntryPoint : IEntryPoint
    {
        // Define the send delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int send(IntPtr s, byte[] buffer, int length, SocketFlags flags);

        // Define the sendto delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int sendto(
            IntPtr socket,
            byte[] buffer,
            int length,
            SocketFlags flags,
            IntPtr to,
            int tolen);

        // Define the WSASend delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int WSASend(IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine);

        // Define the WSASendTo delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int WSASendTo(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            SocketFlags flags,
            IntPtr to,
            int tolen,
            IntPtr overlapped,
            IntPtr completionRoutine);
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int recv(
                IntPtr socket,
                byte[] buffer,
                int length,
                SocketFlags flags);

        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int recvfrom(
                IntPtr socket,
                byte[] buffer,
                int length,
                SocketFlags flags,
                IntPtr from,
                ref int fromlen);

        // Define the WSARecv delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int WSARecv(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            ref SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine);
        // Define the WSARecvFrom delegate
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int WSARecvFrom(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            ref SocketFlags flags,
            IntPtr from,
            ref int fromlen,
            IntPtr overlapped,
            IntPtr completionRoutine);

        // Define the hook function delegate
        public delegate int SendFunc(IntPtr socket, byte[] buffer, int length, SocketFlags flags);
        public delegate int SendToFunc(
            IntPtr socket,
            byte[] buffer,
            int length,
            SocketFlags flags,
            IntPtr to,
            int tolen);
        public delegate int WSASendFunc(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine);
        public delegate int WSASendToFunc(
    IntPtr socket,
    ref WSABuffer buffers,
    uint bufferCount,
    out int bytesTransferred,
    SocketFlags flags,
    IntPtr to,
    int tolen,
    IntPtr overlapped,
    IntPtr completionRoutine);
        public delegate int RecvFunc(IntPtr socket, byte[] buffer, int length, SocketFlags flags);
        public delegate int RecvFromFunc(IntPtr socket, byte[] buffer, int length, SocketFlags flags, IntPtr from, ref int fromlen);
        public delegate int WSARecvFunc(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            ref SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine);
        public delegate int WSARecvFromFunc(
    IntPtr socket,
    ref WSABuffer buffers,
    uint bufferCount,
    out int bytesTransferred,
    ref SocketFlags flags,
    IntPtr from,
    ref int fromlen,
    IntPtr overlapped,
    IntPtr completionRoutine);

        static IntPtr sendPtr = LocalHook.GetProcAddress("ws2_32.dll", "send");
        static IntPtr sendtoPtr = LocalHook.GetProcAddress("ws2_32.dll", "sendto");
        static IntPtr WSASendPtr = LocalHook.GetProcAddress("ws2_32.dll", "WSASend");
        static IntPtr WSASendToPtr = LocalHook.GetProcAddress("ws2_32.dll", "WSASendTo");
        static IntPtr recvPtr = LocalHook.GetProcAddress("ws2_32.dll", "recv");
        static IntPtr recvfromPtr = LocalHook.GetProcAddress("ws2_32.dll", "recvfrom");
        static IntPtr WSARecvPtr = LocalHook.GetProcAddress("ws2_32.dll", "WSARecv");
        static IntPtr WSARecvFromPtr = LocalHook.GetProcAddress("ws2_32.dll", "WSARecvFrom");

        static SendFunc MySendS = (SendFunc)Marshal.GetDelegateForFunctionPointer(sendPtr, typeof(SendFunc));
        static SendToFunc MySendtoS = (SendToFunc)Marshal.GetDelegateForFunctionPointer(sendtoPtr, typeof(SendToFunc));
        static WSASendFunc MyWSASendS = (WSASendFunc)Marshal.GetDelegateForFunctionPointer(WSASendPtr, typeof(WSASendFunc));
        static WSASendToFunc MyWSASendToS = (WSASendToFunc)Marshal.GetDelegateForFunctionPointer(WSASendToPtr, typeof(WSASendToFunc));
        static RecvFunc MyrecvS = (RecvFunc)Marshal.GetDelegateForFunctionPointer(recvPtr, typeof(RecvFunc));
        static RecvFromFunc MyrecvfromS = (RecvFromFunc)Marshal.GetDelegateForFunctionPointer(recvfromPtr, typeof(RecvFromFunc));
        static WSARecvFunc MyWSARecvS = (WSARecvFunc)Marshal.GetDelegateForFunctionPointer(WSARecvPtr, typeof(WSARecvFunc));
        static WSARecvFromFunc MyWSARecvFromS = (WSARecvFromFunc)Marshal.GetDelegateForFunctionPointer(WSARecvFromPtr, typeof(WSARecvFromFunc));

        // Define the send detour function
        public static int MySend(IntPtr socket, byte[] buffer, int length, SocketFlags flags)
        {
            MessageBox.Show("New Message! ");
            try
            {
                // Output the destination IP and packet content to the console
                string destIP = new IPAddress(socket.ToInt64()).ToString();
                string packetContent = Encoding.Default.GetString(buffer, 0, length);
                MessageBox.Show("Destination IP: " + destIP + "\n" + "Packet Content: " + packetContent);
                // Call the original send function
                return send(socket, buffer, length, flags);
            }
            catch (Exception ex)
            {
                MessageBox.Show("123333333333333333333");
                // Handle any exceptions that occur during the hook execution
                Console.WriteLine("Hook error: " + ex.Message);
                return -1;
            }
        }

        // Define the sendto detour function
        static int MySendTo(
            IntPtr socket,
            byte[] buffer,
            int length,
            SocketFlags flags,
            IntPtr to,
            int tolen)
        {
            MessageBox.Show("New Message! ");
            try
            {
                // Output the destination IP and packet content to the console
                IPAddress destIP = new IPAddress(BitConverter.GetBytes(to.ToInt64()));
                string packetContent = Encoding.Default.GetString(buffer, 0, length);
                MessageBox.Show("Destination IP: " + destIP.ToString() + "\n" + "Packet Content: " + packetContent);
                // Create and write to the file
                // Call the original sendto function and get the result
                return sendto(socket, buffer, length, flags, to, tolen);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
                return -1;
            }
        }

        // Define the WSASend detour function
        static int MyWSASend(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine)
        {
            MessageBox.Show("New Message! ");
            try
            {
                // Output the destination IP and packet content to the console
                string destIP = new IPAddress(socket.ToInt64()).ToString();
                MessageBox.Show("Destination IP: " + destIP + "\n" + "Packet Content: ");
                // Create and write to the file
                // Call the original WSASend function and get the result
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return WSASend(socket, ref buffers, bufferCount, out bytesTransferred, flags, overlapped, completionRoutine);
        }
        static int MyWSASendTo(
    IntPtr socket,
    ref WSABuffer buffers,
    uint bufferCount,
    out int bytesTransferred,
    SocketFlags flags,
    IntPtr to,
    int tolen,
    IntPtr overlapped,
    IntPtr completionRoutine)
        {
            MessageBox.Show("New Message! ");
            try
            {
                // Output the destination IP and packet content to the console
                IPAddress destIP = new IPAddress(BitConverter.GetBytes(to.ToInt64()));
                MessageBox.Show("Destination IP: " + destIP.ToString() + "\n" + "Packet Content: " );
                // Call the original WSASendTo function and get the result
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return WSASendTo(socket, ref buffers, bufferCount, out bytesTransferred, flags, to, tolen, overlapped, completionRoutine);
        }

        // Define the WSARecv detour function
        static int MyRecv(IntPtr socket, byte[] buffer, int length, SocketFlags flags)
        {
            MessageBox.Show("New Message! ");
            try
            {
                MessageBox.Show("Recvwwwwww");
                // Call the original WSARecv function and get the result

            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return MyRecv(socket, buffer,length, flags);
        }
        // Define the WSARecv detour function
        static int MyRecvfrom(IntPtr socket, byte[] buffer, int length, SocketFlags flags, IntPtr from, ref int fromlen)
        {
            MessageBox.Show("New Message! ");
            try
            {
                MessageBox.Show("Recvwwwwww");
                // Call the original WSARecv function and get the result

            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return MyRecvfrom(socket, buffer, length, flags, from, ref fromlen);
        }
        // Define the WSARecv detour function
        static int MyWSARecv(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            ref SocketFlags flags,
            IntPtr overlapped,
            IntPtr completionRoutine)
        {
            MessageBox.Show("New Message! ");
            try
            {
                MessageBox.Show("Recvwwwwww");
                // Call the original WSARecv function and get the result
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return WSARecv(socket, ref buffers, bufferCount, out bytesTransferred, ref flags, overlapped, completionRoutine);
        }

        // Define the hook functions for WSASendTo and WSARecvFrom

        static int MyWSARecvFrom(
            IntPtr socket,
            ref WSABuffer buffers,
            uint bufferCount,
            out int bytesTransferred,
            ref SocketFlags flags,
            IntPtr from,
            ref int fromlen,
            IntPtr overlapped,
            IntPtr completionRoutine)
        {
            MessageBox.Show("New Message! ");
            try
            {
                // Output the source IP and received packet content to the console
                IPAddress sourceIP = new IPAddress(BitConverter.GetBytes(from.ToInt64()));
                MessageBox.Show("Source IP: " + sourceIP.ToString() + "\n" + "Received Packet Content: ");
                // Call the original WSARecvFrom function and get the result
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hook error: " + ex.Message);
            }
            return WSARecvFrom(socket, ref buffers, bufferCount, out bytesTransferred, ref flags, from, ref fromlen, overlapped, completionRoutine);
        }

        LocalHook sendHook;
        LocalHook sendtoHook;
        LocalHook WSASendHook;
        LocalHook WSASendToHook;
        LocalHook recvHook;
        LocalHook recvfromHook;
        LocalHook WSARecvHook;
        LocalHook WSARecvFromHook;
        public HookEntryPoint(RemoteHooking.IContext context)
        {
            MessageBox.Show("Main Functions was loaded!");
        }

        public void Run(RemoteHooking.IContext context)
        {
            try
            {
                sendHook = LocalHook.Create(
                    sendPtr,
                    new SendFunc(MySend),
                    this);

                sendtoHook = LocalHook.Create(
                    sendtoPtr,
                    new SendToFunc(MySendTo),
                    this);

                WSASendHook = LocalHook.Create(
                    WSASendPtr,
                    new WSASendFunc(MyWSASend),
                    this);

                WSASendToHook = LocalHook.Create(
                    WSASendToPtr,
                    new WSASendToFunc(MyWSASendTo),
                    this); 

                recvHook = LocalHook.Create(
                    recvPtr,
                    new RecvFunc(MyRecv),
                    this);

                recvfromHook = LocalHook.Create(
                     recvfromPtr,
                    new RecvFromFunc(MyRecvfrom),
                    this);

                WSARecvHook = LocalHook.Create(
                    WSARecvPtr,
                    new WSARecvFunc(MyWSARecv),
                    this);
                WSARecvFromHook = LocalHook.Create(
                    WSARecvFromPtr,
                    new WSARecvFromFunc(MyWSARecvFrom),
                    this);

                sendHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                sendtoHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                WSASendHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                WSASendToHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                recvHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                recvfromHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                WSARecvHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                WSARecvFromHook.ThreadACL.SetExclusiveACL(new int[] { 0 });

                MessageBox.Show("DLL injected successfully!" + RemoteHooking.GetCurrentProcessId());
                RemoteHooking.WakeUpProcess();

                while (true)
                {
                    System.Threading.Thread.Sleep(100);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Injection failed: " + ex.Message);
            }
            finally
            {
                sendHook?.Dispose();
                sendtoHook?.Dispose();
                WSASendHook?.Dispose();
                WSASendToHook?.Dispose();
                recvHook?.Dispose();
                recvfromHook?.Dispose();
                WSARecvHook?.Dispose();
                WSARecvFromHook?.Dispose();
            }
}
}

// Define the WSABuffer structure
[StructLayout(LayoutKind.Sequential)]
public struct WSABuffer
{
    public uint Length;
    public IntPtr Buffer;
}
}