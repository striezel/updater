/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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

using System.Diagnostics;

namespace updater.data
{
    /// <summary>
    /// Holds information about an installer.
    /// </summary>
    public abstract class InstallInfo
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public InstallInfo()
        {
            downloadUrl = null;
            algorithm = HashAlgorithm.Unknown;
            checksum = null;
            publisher = null;
            silentSwitches = null;
        }


        /// <summary>
        /// constructor with initial value parameters
        /// </summary>
        /// <param name="_downloadUrl">URL where the installer can be downloaded</param>
        /// <param name="_algo">hash algorithm that was used to create or verify the checksum</param>
        /// <param name="_check">checksum for the installer - hexadecimal representation</param>
        /// <param name="_publisher">common name of publisher, if file is signed</param>
        /// <param name="_silent">switches for silent installation</param>
        public InstallInfo(string _downloadUrl, HashAlgorithm _algo, string _check, string _publisher, string _silent)
        {
            downloadUrl = _downloadUrl;
            algorithm = _algo;
            checksum = _check;
            publisher = _publisher;
            silentSwitches = _silent;
        }


        /// <summary>
        /// Determines whether or not this instance has checksum information.
        /// </summary>
        /// <returns>Returns true, if there is a checksum.
        /// Returns false, if there is no checksum.</returns>
        public bool hasChecksum()
        {
            return ((algorithm != HashAlgorithm.Unknown)
                && !string.IsNullOrWhiteSpace(checksum));
        }


        /// <summary>
        /// Determines whether or not this instance has signature publisher information.
        /// </summary>
        /// <returns>Returns true, if there is information about a publisher.
        /// Returns false otherwise.</returns>
        public bool hasSignature()
        {
            return !string.IsNullOrWhiteSpace(publisher);
        }


        /// <summary>
        /// Checks whether there is a way to verify the downloaded file.
        /// </summary>
        /// <returns>Returns true, if sufficient information is present.
        /// Returns false, if there is no verification information.</returns>
        public bool canBeVerified()
        {
            return hasChecksum() || hasSignature();
        }


        /// <summary>
        /// Creates a process instance that can be used to perform the update.
        /// </summary>
        /// <param name="downloadedFile">path to the downloaded installer file</param>
        /// <param name="detected">info about the detected software</param>
        /// <returns>Returns a process instance ready to start, if successful.
        /// Returns null, if an error occurred.</returns>
        public abstract Process createInstallProccess(string downloadedFile, DetectedSoftware detected);


        /// <summary>
        /// URL where the installer can be downloaded
        /// </summary>
        public string downloadUrl;


        /// <summary>
        /// hash algorithm that was used to create or verify the checksum
        /// </summary>
        public HashAlgorithm algorithm;


        /// <summary>
        /// checksum for the installer - hexadecimal representation
        /// (e.g. "7772433567cb18608519f649f981e38a0be12c26" for a SHA1 checksum)
        /// </summary>
        public string checksum;


        /// <summary>
        /// common name of the publisher, if file is signed
        /// </summary>
        public string publisher;


        /// <summary>
        /// switches for silent installation
        /// </summary>
        public string silentSwitches;
    } // class
} // namespace
