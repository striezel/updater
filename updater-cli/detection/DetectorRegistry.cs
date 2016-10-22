using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace updater_cli.detection
{
    public class DetectorRegistry
    {
        /// <summary>
        /// tries to get a list of installed software from the registry
        /// </summary>
        /// <returns>Returns a list of installed software.</returns>
        public static List<Entry> detect()
        {
            string keyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
            RegistryKey rKey = Registry.LocalMachine.OpenSubKey(keyName);
            if (null == rKey)
                return null;

            List<Entry> entries = new List<Entry>();
            var subKeys = rKey.GetSubKeyNames();
            foreach (var subName in subKeys)
            {
                RegistryKey subKey = rKey.OpenSubKey(subName);
                if (null != subKey)
                {
                    Entry e = new Entry();
                    object dnObj = subKey.GetValue("DisplayName");
                    if (null != dnObj)
                        e.displayName = dnObj.ToString().Trim();
                    object dvObj = subKey.GetValue("DisplayVersion");
                    if (null != dvObj)
                        e.displayVersion = dvObj.ToString().Trim();
                    object ilObj = subKey.GetValue("InstallLocation");
                    if (null != ilObj)
                        e.installPath = ilObj.ToString().Trim();
                    subKey.Close();
                    subKey = null;
                    if (e.containsInformation())
                        entries.Add(e);
                } //if subKey was opened
            } //foreach
            subKeys = null;
            rKey.Close();
            rKey = null;
            return entries;
        }
    } //class
} 
