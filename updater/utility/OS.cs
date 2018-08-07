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

using System;

namespace updater.utility
{
    /// <summary>
    /// Utility class to get operating system information.
    /// </summary>
    public class OS
    {
        /// <summary>
        /// information about the current operating system
        /// </summary>
        private static readonly OperatingSystem thisOS = Environment.OSVersion;


        /* See https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
         * for information on different version numbers. */


        /// <summary>
        /// Checks whether the system is Windows XP or newer.
        /// </summary>
        /// <param name="os">operating system information
        /// (Leave this at null, if you want to examine the current OS.)</param>
        /// <returns>Returns true, if the OS is WinXP or a newer version.</returns>
        public static bool isWinXPOrNewer(OperatingSystem os = null)
        {
            if (null == os)
                os = thisOS;
            // 5.1 (32bit) or 5.2 (64bit) is WinXP.
            return (os.Platform == PlatformID.Win32NT)
                && ((os.Version.Major > 5)
                || ((os.Version.Major == 5) && (os.Version.Minor >= 1)));
        }


        /// <summary>
        /// Checks whether the system is Windows Vista or newer.
        /// </summary>
        /// <param name="os">operating system information
        /// (Leave this at null, if you want to examine the current OS.)</param>
        /// <returns>Returns true, if the OS is Vista or a newer version.</returns>
        public static bool isWinVistaOrNewer(OperatingSystem os = null)
        {
            if (null == os)
                os = thisOS;
            // Internal version of Vista is 6.0.
            return (os.Platform == PlatformID.Win32NT) && (os.Version.Major >= 6);
        }


        /// <summary>
        /// Checks whether the system is Windows 7 or newer.
        /// </summary>
        /// <param name="os">operating system information
        /// (Leave this at null, if you want to examine the current OS.)</param>
        /// <returns>Returns true, if the OS is Win7 or a newer version.</returns>
        public static bool isWin7OrNewer(OperatingSystem os = null)
        {
            if (null == os)
                os = thisOS;
            // Internal version of Windows 7 is 6.1.
            return (os.Platform == PlatformID.Win32NT)
                && ((os.Version.Major > 6)
                || ((os.Version.Major == 6) && (os.Version.Minor >= 1)));
        }
    } // class
} // namespace
