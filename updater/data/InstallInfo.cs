/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2021  Dirk Stolle

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
        /// Default constructor.
        /// </summary>
        public InstallInfo()
        {
            downloadUrl = null;
            algorithm = HashAlgorithm.Unknown;
            checksum = null;
            signature = Signature.None;
            silentSwitches = null;
        }


        /// <summary>
        /// Constructor with initial value parameters.
        /// </summary>
        /// <param name="_downloadUrl">URL where the installer can be downloaded</param>
        /// <param name="_algo">hash algorithm that was used to create or verify the checksum</param>
        /// <param name="_check">checksum for the installer - hexadecimal representation</param>
        /// <param name="_signature">common name of publisher and expiration date, if file is signed</param>
        /// <param name="_silent">switches for silent installation</param>
        public InstallInfo(string _downloadUrl, HashAlgorithm _algo, string _check, Signature _signature, string _silent)
        {
            downloadUrl = _downloadUrl;
            algorithm = _algo;
            checksum = _check;
            signature = _signature;
            silentSwitches = _silent;
        }


        /// <summary>
        /// Determines whether or not this instance has checksum information.
        /// </summary>
        /// <returns>Returns true, if there is a checksum.
        /// Returns false, if there is no checksum.</returns>
        public bool hasChecksum()
        {
            return (algorithm != HashAlgorithm.Unknown)
                && !string.IsNullOrWhiteSpace(checksum);
        }


        /// <summary>
        /// Determines whether or not this instance has signature information
        /// that can be used for verification.
        /// </summary>
        /// <returns>Returns true, if there is usable information.
        /// Returns false otherwise.</returns>
        public bool hasVerifiableSignature()
        {
            return signature.ContainsData() && !signature.HasExpired();
        }


        /// <summary>
        /// Checks whether there is a way to verify the downloaded file.
        /// </summary>
        /// <returns>Returns true, if sufficient information is present.
        /// Returns false, if there is no verification information.</returns>
        public bool canBeVerified()
        {
            return hasChecksum() || hasVerifiableSignature();
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
        /// signature information, if file is signed
        /// </summary>
        public Signature signature;


        /// <summary>
        /// switches for silent installation
        /// </summary>
        public string silentSwitches;
    } // class
} // namespace
