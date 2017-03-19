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
    public class Pidgin : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Pidgin class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Pidgin).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Pidgin(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Pidgin",
                "2.12.0",
                "^Pidgin$",
                null,
                //Pidgin only has an installer for 32 bit.
                new InstallInfoPidgin(
                    "https://netcologne.dl.sourceforge.net/project/pidgin/Pidgin/2.12.0/pidgin-2.12.0-offline.exe",
                    HashAlgorithm.SHA256,
                    "eda8a422c8d99a1d136a807d0363c9609c05d9f909f6313efb4e2f34f606b484",
                    "/DS=1 /SMS=1 /S",
                    "C:\\Program Files\\Pidgin",
                    "C:\\Program Files (x86)\\Pidgin"),
                null
                );
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return false;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searching for newer version of Pidgin...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://pidgin.im/");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of Pidgin: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reVersion = new Regex("<span class=\"number\">[0-9]+\\.[0-9]+\\.[0-9]+</span>");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string version = matchVersion.Value.Replace("<span class=\"number\">", "").Replace("</span>", "");
            
            //No checksum, only signature.

            //construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = version;
            //32 bit
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            return newInfo;
        }

    } //class
} //namespace
