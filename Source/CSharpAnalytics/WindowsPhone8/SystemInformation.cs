﻿// Copyright (c) Attack Pattern LLC.  All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace CSharpAnalytics.WindowsPhone8
{
    /// <summary>
    /// Obtain system information not conveniently exposed by WinRT APIs.
    /// </summary>
    /// <remarks>
    /// Microsoft doesn't really want you getting this information and makes it difficult.
    /// The techniques used here are not bullet proof but are good enough for analytics.
    /// Do not use these methods or techniques for anything more important than that.
    /// </remarks>
    public class SystemInformation
    {
        /// <summary>
        /// Get the processor architecture of this computer.
        /// </summary>
        /// <returns>The processor architecture of this computer.</returns>
        public static ProcessorArchitecture GetProcessorArchitecture()
        {
            try
            {
                var sysInfo = new _SYSTEM_INFO();
                GetNativeSystemInfo(ref sysInfo);

                return Enum.IsDefined(typeof(ProcessorArchitecture), sysInfo.wProcessorArchitecture)
                    ? (ProcessorArchitecture)sysInfo.wProcessorArchitecture
                    : ProcessorArchitecture.UNKNOWN;
            }
            catch
            {
            }

            return ProcessorArchitecture.UNKNOWN;
        }

        [DllImport("kernel32.dll")]
        static extern void GetNativeSystemInfo(ref _SYSTEM_INFO lpSystemInfo);

        [StructLayout(LayoutKind.Sequential)]
        struct _SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public UIntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        };
    }

    public enum ProcessorArchitecture : ushort
    {
        INTEL = 0,
        MIPS = 1,
        ALPHA = 2,
        PPC = 3,
        SHX = 4,
        ARM = 5,
        IA64 = 6,
        ALPHA64 = 7,
        MSIL = 8,
        AMD64 = 9,
        IA32_ON_WIN64 = 10,
        UNKNOWN = 0xFFFF
    }
}