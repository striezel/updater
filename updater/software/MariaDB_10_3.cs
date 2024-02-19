/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2023, 2024  Dirk Stolle

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
    /// Handles updates of MariaDB 10.3.
    /// </summary>
    public sealed class MariaDB_10_3: MariaDB_Base
    {
        /// <summary>
        /// publisher of signed binaries for MariaDB 10.3
        /// </summary>
        private new const string publisherX509 = "CN=MariaDB Corporation Ab, OU=Connectors, O=MariaDB Corporation Ab, L=Espoo, C=FI";


        /// <summary>
        /// expiration date of the certificate for MariaDB 10.3
        /// </summary>
        private static new readonly DateTime certificateExpiration = new(2024, 1, 4, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public MariaDB_10_3(bool autoGetNewer)
            : base(autoGetNewer, "10.3")
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "10.3.39";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("MariaDB Server 10.3",
                version,
                null, // no 32 bit installer
                "^MariaDB 10\\.3 \\(x64\\)$",
                null, // no 32 bit installer
                new InstallInfoMsi(
                    "https://downloads.mariadb.org/rest-api/mariadb/" + version + "/mariadb-" + version + "-winx64.msi",
                    HashAlgorithm.SHA256,
                    "96a5bb8765df9bf78bd8f136390050c5fdc1c3119963792b11a7ed80df004696",
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
            return new DateTime(2023, 5, 25, 23, 59, 59, DateTimeKind.Utc);
        }
    }
}
