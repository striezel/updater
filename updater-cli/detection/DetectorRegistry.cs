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
using Microsoft.Win32;

namespace updater_cli.detection
{
    /// <summary>
    /// class to detect installed software via registry
    /// </summary>
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
