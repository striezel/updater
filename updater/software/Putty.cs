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

using updater.data;
using System;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace updater.software
{
    public class Putty : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Putty class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Putty).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Putty(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name on signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Simon Tatham, O=Simon Tatham, L=Cambridge, S=Cambridgeshire, C=GB";


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("PuTTY",
                "0.69",
                "^PuTTY release [0-9]\\.[0-9]+$",
                "^PuTTY release [0-9]\\.[0-9]+ \\(64\\-bit\\)$",
                //32 bit installer
                new InstallInfoMsi(
                    "https://the.earth.li/~sgtatham/putty/0.69/w32/putty-0.69-installer.msi",
                    HashAlgorithm.SHA512,
                    "436c74c6e71e18e2c766664a75f09380c63d15f769c9eddb6c8f569a8ad372e9457bc06ce7d6443ee33a327e03d395f362681e79a573792a3bfad9115c577eda",
                    publisherX509,
                    "/qn /norestart",
                    "C:\\Program Files\\PuTTY",
                    "C:\\Program Files (x86)\\PuTTY"),
                //64 bit installer
                new InstallInfoMsi(
                    "https://the.earth.li/~sgtatham/putty/0.69/w64/putty-64bit-0.69-installer.msi",
                    HashAlgorithm.SHA512,
                    "b1d6077279f5587841aa3fb0f6c268b0e3cd6cae630d55934863f80c6a5e5de333a1995aea24cffb18ff1c04b787ff6b844fec5641aa8e39ae6c6e18fd1b67e5",
                    publisherX509,
                    "/qn /norestart",
                    null,
                    "C:\\Program Files\\PuTTY")
                );
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "putty" };
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
            logger.Debug("Searching for newer version of PuTTY...");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://the.earth.li/~sgtatham/putty/latest/");
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            string newLocation = null;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer PuTTY version: " + ex.Message);
                return null;
            }

            Regex reVersion = new Regex("/[0-9]+\\.[0-9]+/");
            Match matchVersion = reVersion.Match(newLocation);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Value.Replace("/", "");

            //Checksums are in a file like https://the.earth.li/~sgtatham/putty/0.68/sha512sums
            string sha512sums = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512sums = client.DownloadString("https://the.earth.li/~sgtatham/putty/" + newVersion + "/sha512sums");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of PuTTY: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reHash32 = new Regex("[0-9a-f]{128}  w32/putty\\-" + Regex.Escape(newVersion) + "\\-installer\\.msi");
            Match matchHash32 = reHash32.Match(sha512sums);
            if (!matchHash32.Success)
                return null;
            string hash32 = matchHash32.Value.Substring(0, 128);

            Regex reHash64 = new Regex("[0-9a-f]{128}  w64/putty\\-64bit\\-" + Regex.Escape(newVersion) + "\\-installer\\.msi");
            Match matchHash64 = reHash64.Match(sha512sums);
            if (!matchHash64.Success)
                return null;
            string hash64 = matchHash64.Value.Substring(0, 128);

            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = hash32;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = hash64;
            return newInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// whether or not a separate process must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate proess returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.displayVersion))
                return false;

            return string.Compare(detected.displayVersion, "0.68") < 0;
        }


        /// <summary>
        /// returns a process that must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            //We do not need a pre-update process, if the version is 0.68 or
            // newer, because that one uses MSI.
            // We also cannot create a process, if the install directory is
            // unknown.
            if (string.IsNullOrWhiteSpace(detected.displayVersion)
                || string.IsNullOrWhiteSpace(detected.installPath)
                || (string.Compare(detected.displayVersion, "0.68") >= 0))
                return null;

            var processes = new List<Process>();
            //first process:
            // delete putty.exe to disable prompt that deletes settings (we want to keep them)
            var proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
            proc.StartInfo.Arguments = "/C del \""
                + System.IO.Path.Combine(detected.installPath, "putty.exe") + "\"";
            processes.Add(proc);
            //second process: uninstall old PuTTY
            proc = new Process();
            proc.StartInfo.FileName = System.IO.Path.Combine(detected.installPath, "unins000.exe");
            proc.StartInfo.Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            //Simple version string comparison.
            return (string.Compare(detected.displayVersion, info().newestVersion, true) < 0);
        }
    } //class
} //namesoace
