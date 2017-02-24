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
        public static List<data.DetectedSoftware> detect()
        {
            if (Environment.Is64BitOperatingSystem)
            {
                var data64 = detectSingleView(RegistryView.Registry64);
                var data32 = detectSingleView(RegistryView.Registry32);
                if ((data64 == null) || (data32 == null))
                    return null;
                data64.AddRange(data32);
                return data64;
            } //if 64 bit OS
            else
            {
                return detectSingleView(RegistryView.Registry32);
            }
        }


        /// <summary>
        /// gets a list of installed software from the registry, using a specified registry view
        /// </summary>
        /// <param name="view">the registry view (64 bit or 32 bit)</param>
        /// <returns>Returns a list of installed software.</returns>
        private static List<data.DetectedSoftware> detectSingleView(RegistryView view)
        {
            RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            const string keyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
            RegistryKey rKey = baseKey.OpenSubKey(keyName);
            if (null == rKey)
            {
                baseKey.Close();
                baseKey = null;
                return null;
            }

            List<data.DetectedSoftware> entries = new List<data.DetectedSoftware>();
            var subKeys = rKey.GetSubKeyNames();
            foreach (var subName in subKeys)
            {
                RegistryKey subKey = rKey.OpenSubKey(subName);
                if (null != subKey)
                {
                    data.DetectedSoftware e = new data.DetectedSoftware();
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
                    switch (view)
                    {

                        case RegistryView.Registry64:
                            e.appType = data.ApplicationType.Bit64;
                            break;
                        case RegistryView.Registry32:
                            e.appType = data.ApplicationType.Bit32;
                            break;
                        case RegistryView.Default:
                        default:
                            throw new ArgumentOutOfRangeException(nameof(view), "Unknown registry view type!");
                    } //switch
                    if (e.containsInformation())
                        entries.Add(e);
                } //if subKey was opened
            } //foreach
            subKeys = null;
            rKey.Close();
            rKey = null;
            baseKey.Close();
            baseKey = null;
            return entries;
        }
    } //class
} //namespace
