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
    public class WinSCP : ISoftware
    {
        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public AvailableSoftware info()
        {
            return new AvailableSoftware("WinSCP", "5.9.4",
                "^WinSCP [1-9]+\\.[0-9]+\\.[0-9]+$", null,
                new InstallInfoExe(
                    "https://winscp.net/download/WinSCP-5.9.4-Setup.exe",
                    HashAlgorithm.SHA256,
                    "af062b32c907ee1d51de82cadb570171750a51e7dd3d953bb8f24282c3db642d",
                    "/VERYSILENT /NORESTART",
                    "C:\\Program Files\\WinSCP",
                    "C:\\Program Files (x86)\\WinSCP"),
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
                    htmlCode = client.DownloadString("https://winscp.net/eng/download.php");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of WinSCP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reExe = new Regex("WinSCP\\-[1-9]+\\.[0-9]+\\.[0-9]+\\-Setup\\.exe");
            Match matchExe = reExe.Match(htmlCode);
            if (!matchExe.Success)
                return null;
            //extract new version number
            string newVersion = matchExe.Value.Replace("WinSCP-", "").Replace("-Setup.exe", "");
            if (string.Compare(newVersion, info().newestVersion) < 0)
                return null;
            //version number should match usual scheme, e.g. 5.x.y, where x and y are digits
            Regex version = new Regex("^[1-9]+\\.[0-9]+\\.[0-9]+$");
            if (!version.IsMatch(newVersion))
                return null;

            //Readme (e.g. https://winscp.net/download/WinSCP-5.9.4-ReadMe.txt) contains hash.
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://winscp.net/download/WinSCP-" + newVersion + "-ReadMe.txt");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of WinSCP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //extract hash - .exe occurs first, so first hash is the one we want
            Regex hash = new Regex("SHA\\-256\\: [0-9a-f]{64}");
            Match matchHash = hash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash = matchHash.Value.Replace("SHA-256: ", "").Trim();
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
