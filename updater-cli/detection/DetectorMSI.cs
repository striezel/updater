using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace updater_cli.detection
{
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
        public static List<Entry> detect()
        {
            List<Entry> entries = new List<Entry>();
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
                var e = new Entry(sbProductName.ToString(), null, sbInstallDir.ToString());
                if (e.containsInformation())
                    entries.Add(e);
            } //while
            return entries;
        }
    } //class
} //namespace
