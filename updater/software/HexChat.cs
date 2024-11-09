/*
    This file is part of the updater command line interface.
    Copyright (C) 2023, 2024  Dirk Stolle

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

using System.Collections.Generic;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of HexChat.
    /// </summary>
    public class HexChat : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public HexChat(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("HexChat",
                "2.16.2",
                "^HexChat$",
                "^HexChat$",
                new InstallInfoExe(
                    "https://github.com/hexchat/hexchat/releases/download/v2.16.2/HexChat.2.16.2.x86.exe",
                    HashAlgorithm.SHA256,
                    "830f32073130faaeaba22b7e4f7f8b21ecd476a1236fabb675b7de5a8bf8c026",
                    Signature.None,
                    "/VERYSILENT /NORESTART"),
                new InstallInfoExe(
                    "https://github.com/hexchat/hexchat/releases/download/v2.16.2/HexChat.2.16.2.x64.exe",
                    HashAlgorithm.SHA256,
                    "39da96a323ba98583e716a7ee5af1a02a34935dbe3b0865b54c65ce7784e0828",
                    Signature.None,
                    "/VERYSILENT /NORESTART")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["hexchat"];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return false;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            // HexChat 2.16.2 is the final release, there will be no newer versions.
            // See <https://hexchat.github.io/news/2.16.2.html> for more information.
            return null;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(2)
            {
                "hexchat", // HexChat itself
                "thememan" // theme manager
            };
        }
    } // class
} // namespace
