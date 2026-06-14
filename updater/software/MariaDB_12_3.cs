/*
    This file is part of the updater command line interface.
    Copyright (C) 2026  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// Handles updates of MariaDB 12.3.
    /// </summary>
    public sealed class MariaDB_12_3 : MariaDB_Base
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public MariaDB_12_3(bool autoGetNewer)
            : base(autoGetNewer, "12.3")
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "12.3.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("MariaDB Server 12.3",
                version,
                null, // no 32-bit installer
                "^MariaDB 12\\.3 \\(x64\\)$",
                null, // no 32-bit installer
                new InstallInfoMsi(
                    "https://downloads.mariadb.org/rest-api/mariadb/" + version + "/mariadb-" + version + "-winx64.msi",
                    HashAlgorithm.SHA256,
                    "5a964e4f1c719aa1d4b065236a0a7a343cb7592e6a21d1acb6fd1d426683b912",
                    signature,
                    "/qn /norestart")
                );
        }


        /// <summary>
        /// Gets the date when this branch of MariaDB reaches its end of life.
        /// </summary>
        /// <returns>Returns the end of life date for this release branch.</returns>
        public override DateTime EndOfLife()
        {
            // TODO: Find proper date. Currently, it's only listed as "June 2029"
            // on the homepage, but the exact day is still unspecified.
            return new DateTime(2029, 6, 30, 23, 59, 59, DateTimeKind.Utc);
        }
    }
}
