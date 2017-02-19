/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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

using updater_cli.data;
using System;
using System.Net;
using System.Text.RegularExpressions;

namespace updater_cli.software
{
    public class KeePass : ISoftware
    {
        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public AvailableSoftware info()
        {
            return new AvailableSoftware("KeePass", "2.35",
                "^KeePass Password Safe [2-9]\\.[0-9]{2}$", null,
                new InstallInfoExe(
                    "https://kent.dl.sourceforge.net/project/keepass/KeePass%202.x/2.35/KeePass-2.35-Setup.exe",
                    HashAlgorithm.SHA256,
                    "6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                    "/VERYSILENT",
                    "C:\\Program Files\\KeePass Password Safe 2",
                    "C:\\Program Files (x86)\\KeePass Password Safe 2"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public AvailableSoftware searchForNewer()
        {
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("http://keepass.info/integrity.html");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of KeePass: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reExe = new Regex("&lt;KeePass\\-[2-9]\\.[0-9]{2}\\-Setup\\.exe&gt;");
            Match matchExe = reExe.Match(htmlCode);
            if (!matchExe.Success)
                return null;
            //MSI follows after .exe
            Regex reMsi = new Regex("&lt;KeePass\\-[2-9]\\.[0-9]{2}\\.msi&gt;");
            Match matchMsi = reMsi.Match(htmlCode, matchExe.Index + 1);
            if (!matchMsi.Success)
                return null;
            //extract new version number
            string newVersion = matchExe.Value.Replace("&lt;KeePass-", "").Replace("-Setup.exe&gt;", "");
            if (string.Compare(newVersion, info().newestVersion) < 0)
                return null;
            //version number should match usual scheme, e.g. 2.xx, where xx are two digits
            Regex version = new Regex("^[2-9]\\.[0-9]{2}$");
            if (!version.IsMatch(newVersion))
                return null;

            //extract hash
            Regex hash = new Regex("SHA256       \\: [0-9A-F ]+");
            Match matchHash = hash.Match(htmlCode, matchExe.Index + 1);
            if (!matchHash.Success)
                return null;
            if (matchHash.Index > matchMsi.Index)
                return null;
            //find second part of hash
            Regex hash2 = new Regex("[0-9A-F ]+");
            Match matchHash2 = hash2.Match(htmlCode, matchHash.Index + matchHash.Length);
            if (!matchHash2.Success)
                return null;
            if (matchHash2.Index > matchMsi.Index)
                return null;
            string newHash = matchHash.Value.Replace("SHA256       : ", "").Trim()
                + " " + matchHash2.Value.Trim();
            //construct new version information
            var newInfo = info();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = newHash;
            return newInfo;
        }

    } //class
} //namespace
