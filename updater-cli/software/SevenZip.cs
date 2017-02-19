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

using System;
using System.Net;
using System.Text.RegularExpressions;
using updater_cli.data;

namespace updater_cli.software
{
    public class SevenZip : ISoftware
    {
        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public AvailableSoftware info()
        {
            return new AvailableSoftware("7-Zip", "16.04",
                "^7\\-Zip [0-9]+\\[0-9]{2}$",
                "^7\\-Zip [0-9]+\\[0-9]{2} \\(x64\\)$",
                new InstallInfoExe(
                    "http://www.7-zip.org/a/7z1604.exe",
                    HashAlgorithm.SHA256,
                    "dbb2b11dea9f4432291e2cbefe14ebe05e021940e983a37e113600eee55daa95",
                    "/S",
                    "C:\\Program Files\\7-Zip",
                    "C:\\Program Files (x86)\\7-Zip"),
                new InstallInfoExe(
                    "http://www.7-zip.org/a/7z1604-x64.exe",
                    HashAlgorithm.SHA256,
                    "9bb4dc4fab2a2a45c15723c259dc2f7313c89a5ac55ab7c3f76bba26edc8bcaa",
                    "/S",
                    null,
                    "C:\\Program Files\\7-Zip")
                );
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
                    htmlCode = client.DownloadString("http://www.7-zip.org/");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of 7-Zip: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reVersion = new Regex("Download 7\\-Zip [0-9]+\\.[0-9]{2} \\([0-9]{4}\\-[0-9]{2}\\-[0-9]{2}\\) for Windows");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;

            string version = matchVersion.Value.Replace("Download 7-Zip", "").Trim();
            int idx = version.IndexOf(' ');
            if (idx < 0)
                return null;
            version = version.Remove(idx);
            if (string.IsNullOrWhiteSpace(version))
                return null;

            //construct new information
            var newInfo = info();
            newInfo.newestVersion = version;
            string newVersionWithoutDot = version.Replace(".", "");
            //32 bit
            newInfo.install32Bit.downloadUrl = "http://www.7-zip.org/a/7z" + newVersionWithoutDot + ".exe";
            // The official 7-zip.org site does not provide any checksums,
            // so we have to do without.
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install32Bit.checksum = null;
            // 64 bit
            newInfo.install64Bit.downloadUrl = "http://www.7-zip.org/a/7z" + newVersionWithoutDot + "-x64.exe";
            // The official 7-zip.org site does not provide any checksums,
            // so we have to do without.
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.checksum = null;
            return newInfo;
        }
    } //class
} //namespace
