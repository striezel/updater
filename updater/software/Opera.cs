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
using updater.data;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace updater.software
{
    public class Opera : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Opera class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Opera).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Opera(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Opera",
                "44.0.2510.1218",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/44.0.2510.1218/win/Opera_44.0.2510.1218_Setup.exe",
                    HashAlgorithm.SHA256,
                    "d854aff85480989e3a903444ab4e6598fd20bbea37e589279b0cf9a93057f819",
                    "/silent /norestart /launchopera 0 /setdefaultbrowser 0 /allusers",
                    "C:\\Program Files\\Opera",
                    "C:\\Program Files (x86)\\Opera"),
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/44.0.2510.1218/win/Opera_44.0.2510.1218_Setup_x64.exe",
                    HashAlgorithm.SHA256,
                    "dae0985cfb3931e81e488056db169c5b520a28e8190e559b467d6cdf553afb57",
                    "/silent /norestart /launchopera 0 /setdefaultbrowser 0 /allusers",
                    null,
                    "C:\\Program Files\\Opera")
                    );
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "opera" };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searching for newer version of Opera...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.geo.opera.com/pub/opera/desktop/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Opera: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //Search for all knonwn versions.
            Regex reVersion = new Regex("\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/\"");
            var matches = reVersion.Matches(htmlCode);
            if (matches.Count == 0)
                return null;
            //Add found versions to a list ...
            List<versions.Quartet> versions = new List<versions.Quartet>();
            foreach (Match match in matches)
            {
                if (!match.Success)
                    return null;
                string version = match.Value.Substring(1).Replace("/\"", "");
                versions.Add(new versions.Quartet(version));
            } //foreach
            // ... and sort them from earliest to latest.
            versions.Sort();

            //Now find the latest version that already has a win/ directory.
            string newVersion = null;
            for (int i = versions.Count - 1; i >= 0; i--)
            {
                htmlCode = null;
                bool exists = false;
                using (var client = new WebClient())
                {
                    try
                    {
                        htmlCode = client.DownloadString("https://get.geo.opera.com/ftp/pub/opera/desktop/" + versions[i].full() + "/win/");
                        exists = true;
                    }
                    catch (Exception)
                    {
                        //Not found.
                        exists = false;
                    }
                    client.Dispose();
                } //using
                if (exists)
                {
                    newVersion = versions[i].full();
                    break;
                } //if
            } //for

            if (null == newVersion)
                return null;

            var newInfo = knownInfo();
            if (newVersion == newInfo.newestVersion)
                return newInfo;

            //Look into "https://get.geo.opera.com/ftp/pub/opera/info/md5sum.txt".
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.geo.opera.com/ftp/pub/opera/info/md5sum.txt");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while finding checksums for newer version of Opera: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //checksum for 32 bit installer
            Regex reg = new Regex("[0-9a-f]{32}  pub/opera/desktop/" + Regex.Escape(newVersion) + "/win/Opera_" + Regex.Escape(newVersion) + "_Setup\\.exe");
            Match m = reg.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum32 = m.Value.Substring(0, 32);

            //checksum for 64 bit installer
            reg = new Regex("[0-9a-f]{32}  pub/opera/desktop/" + Regex.Escape(newVersion) + "/win/Opera_" + Regex.Escape(newVersion) + "_Setup_x64\\.exe");
            m = reg.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum64 = m.Value.Substring(0, 32);

            //construct new version information based on old information
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = checksum32;
            newInfo.install32Bit.algorithm = HashAlgorithm.MD5;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = checksum64;
            newInfo.install64Bit.algorithm = HashAlgorithm.MD5;
            return newInfo;
        }
    } //class
} //namespace
