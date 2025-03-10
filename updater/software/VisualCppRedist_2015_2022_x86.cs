/*
    This file is part of the updater command line interface.
    Copyright (C) 2025  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// Handles updates of Microsoft Visual C++ 2015-2022 Redistributable (x86).
    /// </summary>
    public class VisualCppRedist_2015_2022_x86 : VisualCppRedist_2015_2022_Common
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public VisualCppRedist_2015_2022_x86(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoExe_VCRedist(
                "https://aka.ms/vs/17/release/vc_redist.x86.exe",
                HashAlgorithm.Unknown,
                null,
                signature,
                "/quiet /norestart");
            return new AvailableSoftware(
                "MSVC++ 2015-2022 Redistributable (x86)",
                currentVersion,
                "^Microsoft Visual C\\+\\+ 2015\\-2022 Redistributable \\(x86\\) \\- 14\\.[0-9]+\\.[0-9]+$",
                "^Microsoft Visual C\\+\\+ 2015\\-2022 Redistributable \\(x86\\) \\- 14\\.[0-9]+\\.[0-9]+$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["vcredist_2015_2022_x86", "vcredist_2015_2022", "vcredist_x86", "vcredist"];
        }
    } // class
} // namespace
