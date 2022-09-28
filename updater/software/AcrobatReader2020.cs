/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

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
using System.Collections.Generic;
using System.Diagnostics;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Adobe Acrobat Reader 2020.
    /// </summary>
    public class AcrobatReader2020: NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// publisher name for signed executables of Reader 2020
        /// </summary>
        private const string publisherX509 = "OU=Acrobat DC, O=Adobe Inc., L=San Jose, S=ca, C=US, SERIALNUMBER=2748129, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2 = Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2021, 2, 3, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        public AcrobatReader2020()
            : base(false)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "20.001.30010";
            var installer = new InstallInfoMsiPatch(
                "ftp://ftp.adobe.com/pub/adobe/reader/win/Acrobat2020/2000130010/AcroRdr2020Upd2000130010_MUI.msp",
                HashAlgorithm.SHA256,
                "0ec1a792ccb902f8c50d456db807cb9512e07e90c1fda9060da2e6ce92982cd5",
                new Signature(publisherX509, certificateExpiration),
                "/qn /norestart"
                );
            return new AvailableSoftware("Acrobat Reader 2020",
                version,
                "^Adobe Acrobat Reader 2020 MUI$",
                "^Adobe Acrobat Reader 2020 MUI$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "acrobat-reader-2020", "acrobat-reader", "acrobat" };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            throw new NotImplementedException("Search for new releases of Acrobat Reader 2020 is not implemented.");
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "AcroRd32",
            };
        }
    } // class
} // namespace
