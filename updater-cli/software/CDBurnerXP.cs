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
    public class CDBurnerXP : ISoftware
    {
        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public AvailableSoftware info()
        {
            return new AvailableSoftware("CDBurnerXP", "4.5.7.6521",
                "^CDBurnerXP$",
                "^CDBurnerXP \\(64 Bit\\)$",
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_4.5.7.6521.msi",
                    HashAlgorithm.SHA256,
                    "c38d057b27fa8428e13c21bd749ef690b4969fab14518fb07c99ad667db6167e",
                    "/qn /norestart",
                    "C:\\Program Files\\CDBurnerXP",
                    "C:\\Program Files (x86)\\CDBurnerXP"),
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_x64_4.5.7.6521.msi",
                    HashAlgorithm.SHA256,
                    "3a665bcbaa60c229303a2676507d4753089a03cfe5e890f7c72fe83e298fa153",
                    "/qn /norestart",
                    null,
                    "C:\\Program Files\\CDBurnerXP")
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
                    htmlCode = client.DownloadString("https://cdburnerxp.se/download");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of CDBurnerXP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reMsi = new Regex("cdbxp_setup_[1-9]\\.[0-9]\\.[0-9]\\.[0-9]{4}\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Value.Replace("cdbxp_setup_", "").Replace(".msi", "");
            
            //construct new version information
            var newInfo = info();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            return newInfo;
        }

    } //class
} //namespace
