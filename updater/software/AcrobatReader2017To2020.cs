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
    /// Handles updates of Adobe Acrobat Reader 2017 to Adobe Acrobat Reader 2020.
    /// </summary>
    public class AcrobatReader2017To2020: AbstractSoftware
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
        public AcrobatReader2017To2020()
            : base(false)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "20.0.0.0";
            var installer = new InstallInfoExe(
                "https://ardownload2.adobe.com/pub/adobe/reader/win/Acrobat2020/2000130002/AcroRdr20202000130002_MUI.exe",
                HashAlgorithm.SHA256,
                "72f25de9f1477f105b806a697e2d20638b9fa729b280092bae480cd9ef519496",
                new Signature(publisherX509, certificateExpiration),
                "/sAll /re /msi DISABLE_FIU_CHECK=1"
                );
            return new AvailableSoftware("Acrobat Reader 2017",
                version,
                "^Adobe Acrobat Reader 2017 MUI$",
                "^Adobe Acrobat Reader 2017 MUI$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "acrobat-reader-2017", "acrobat-reader", "acrobat" };
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
            throw new NotImplementedException("There are no new releases for Acrobat Reader 2017, it reached End Of Life.");
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

        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This may return an empty list, if no processes need to be run
        /// before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            // Uninstall Acrobat Reader 2017 first.
            var processes = new List<Process>(1);
            var proc = new Process();
            proc.StartInfo.FileName = "msiexec.exe";
            proc.StartInfo.Arguments = "/qn /x{AC76BA86-7AD7-FFFF-7B44-AE1108756300}";
            processes.Add(proc);
            return processes;
        }
    } // class
} // namespace
