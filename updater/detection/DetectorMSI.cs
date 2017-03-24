/*
    updater, command line interface
    Copyright (C) 2016  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace updater.detection
{
    /// <summary>
    /// class to detect installed software via MSI.dll
    /// </summary>
    public class DetectorMSI
    {
        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        static extern Int32 MsiGetProductInfo(string product, string property,
            [Out] StringBuilder valueBuf, ref Int32 len);

        [DllImport("msi.dll", SetLastError = true)]
        static extern int MsiEnumProducts(int iProductIndex,
            StringBuilder lpProductBuf);


        /// <summary>
        /// tries to get a list of installed software from the MSI cache
        /// </summary>
        /// <returns>Returns a list of installed software.</returns>
        public static List<data.DetectedSoftware> detect()
        {
            List<data.DetectedSoftware> entries = new List<data.DetectedSoftware>();
            StringBuilder sbProductCode = new StringBuilder(39);
            int iIdx = 0;
            while (0 == MsiEnumProducts(iIdx++, sbProductCode))
            {
                Int32 productNameLen = 512;
                StringBuilder sbProductName = new StringBuilder(productNameLen);
                MsiGetProductInfo(sbProductCode.ToString(), "ProductName", sbProductName, ref productNameLen);
                Int32 installDirLen = 1024;
                StringBuilder sbInstallDir = new StringBuilder(installDirLen);
                MsiGetProductInfo(sbProductCode.ToString(), "InstallLocation", sbInstallDir, ref installDirLen);
                var e = new data.DetectedSoftware(sbProductName.ToString(), null, sbInstallDir.ToString());
                if (e.containsInformation())
                    entries.Add(e);
            } //while
            return entries;
        }
    } //class
} //namespace
