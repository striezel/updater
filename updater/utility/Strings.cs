/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2024  Dirk Stolle

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

namespace updater.utility
{
    /// <summary>
    /// utility class for string handling
    /// </summary>
    public static class Strings
    {
        /// <summary>
        /// Returns a string representation of a boolean value.
        /// </summary>
        /// <param name="b">a boolean value</param>
        /// <returns>Returns "yes", if b is true.
        /// Returns "no" otherwise.</returns>
        public static string boolToYesNo(bool b)
        {
            if (b)
                return "yes";
            else
                return "no";
        }


        /// <summary>
        /// Returns a string representation of the application type.
        /// </summary>
        /// <param name="appT">the application type</param>
        /// <returns>Returns a string indicating the application type.</returns>
        public static string appTypeToString(data.ApplicationType appT)
        {
            return appT switch
            {
                data.ApplicationType.Bit32 => "32-bit",
                data.ApplicationType.Bit64 => "64-bit",
                _ => "unknown",
            };
        }


        /// <summary>
        /// Removes a backslash from the end of the string.
        /// </summary>
        /// <param name="val">the string</param>
        /// <returns>Returns the string with the backslash removed.</returns>
        public static string removeTrailingBackslash(string val)
        {
            if (string.IsNullOrWhiteSpace(val))
                return val;

            int len = val.Length;
            if (val[len - 1] == '\\')
                return val.Remove(len - 1);
            else
                return val;
        }
    } // class
} // namespace
