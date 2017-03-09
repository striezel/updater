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
    public class VLC : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public VLC(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("VLC media player", "2.2.4",
                "^VLC media player$",
                "^VLC media player$",
                //32 bit installer
                new InstallInfoExe(
                    "http://get.videolan.org/vlc/2.2.4/win32/vlc-2.2.4-win32.exe",
                    HashAlgorithm.SHA256,
                    "f4a4b8897e86f52a319ee4568e62be9cda1bcb2341e798da12e359d81cb36e51",
                    "/S",
                    "C:\\Program Files\\VideoLAN\\VLC",
                    "C:\\Program Files (x86)\\VideoLAN\\VLC"),
                //64 bit installer
                new InstallInfoExe(
                    "http://get.videolan.org/vlc/2.2.4/win64/vlc-2.2.4-win64.exe",
                    HashAlgorithm.SHA256,
                    "a283b1913c8905c4d58787f34b4a85f28f3f77c4157bee554e3e70441e6e75e4",
                    "/S",
                    null,
                    "C:\\Program Files\\VideoLAN\\VLC")
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
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.videolan.org/vlc/last/");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of VLC: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reTarXz = new Regex("vlc\\-[1-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\.tar\\.xz");
            Match matchTarXz = reTarXz.Match(htmlCode);
            if (!matchTarXz.Success)
                return null;
            //extract new version number
            string newVersion = matchTarXz.Value.Replace("vlc-", "").Replace(".tar.xz", "");
            if (string.Compare(newVersion, info().newestVersion) < 0)
                return null;
            //version number should match usual scheme, e.g. 5.x.y, where x and y are digits
            Regex version = new Regex("^[1-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?$");
            if (!version.IsMatch(newVersion))
                return null;

            //There are extra files for hashes:
            // https://get.videolan.org/vlc/last/win32/vlc-2.2.4-win32.exe.sha256 for 32 bit
            // and https://get.videolan.org/vlc/last/win64/vlc-2.2.4-win64.7z.sha256 for 64 bit.
            var newHashes = new System.Collections.Generic.List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                htmlCode = null;
                using (var client = new WebClient())
                {
                    try
                    {
                        htmlCode = client.DownloadString("https://get.videolan.org/vlc/last/win" + bits + "/vlc-" + newVersion + "-win" + bits + ".exe.sha256");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Exception occurred while checking for newer version of VLC: " + ex.Message);
                        return null;
                    }
                    client.Dispose();
                } //using

                //extract hash
                Regex reHash = new Regex("^[0-9a-f]{64} \\*vlc\\-" + Regex.Escape(newVersion) + "\\-win" + bits + ".exe");
                Match matchHash = reHash.Match(htmlCode);
                if (!matchHash.Success)
                    return null;
                string newHash = matchHash.Value.Substring(0, 64).Trim();
                newHashes.Add(newHash);
            } //foreach

            //construct new version information
            var newInfo = info();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = newHashes[0];
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = newHashes[1];
            return newInfo;
        }
    } //class
} //namesoace
