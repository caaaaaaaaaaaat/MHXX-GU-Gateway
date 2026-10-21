# SPDX-License-Identifier: GPL-3.0-or-later
if(-not ('CaptureUdp' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
public static class CaptureUdp {
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int kind, uint reserved);
    public static string[] At(int port) {
        int size=0; GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1, 0);
        if(size<=0) throw new Exception("UDP table size unavailable");
        IntPtr data=Marshal.AllocHGlobal(size);
        try {
            if(GetExtendedUdpTable(data,ref size,false,2,1,0)!=0) throw new Exception("UDP table read failed");
            int count=Marshal.ReadInt32(data); var found=new List<string>();
            for(int i=0;i<count;i++) {
                int offset=4+i*12;
                uint addr=unchecked((uint)Marshal.ReadInt32(data,offset));
                int raw=Marshal.ReadInt32(data,offset+4);
                int p=((raw&255)<<8)|((raw>>8)&255);
                int owner=Marshal.ReadInt32(data,offset+8);
                if(p==port) found.Add(owner+"|"+new IPAddress(BitConverter.GetBytes(addr)).ToString()+"|"+p);
            }
            return found.ToArray();
        } finally {Marshal.FreeHGlobal(data);}
    }
}
'@
}
