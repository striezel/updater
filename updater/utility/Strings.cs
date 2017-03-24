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

namespace updater.utility
{
    /// <summary>
    /// utility class for string handling
    /// </summary>
    public class Strings
    {
        /// <summary>
        /// returns a string representation of a boolean value
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
        /// returns a string representation of the application type
        /// </summary>
        /// <param name="appT">the application type</param>
        /// <returns>Returns a string indicating the appliation type.</returns>
        public static string appTypeToString(data.ApplicationType appT)
        {
            switch (appT)
            {
                
                case data.ApplicationType.Bit32:
                    return "32 bit";
                case data.ApplicationType.Bit64:
                    return "64 bit";
                case data.ApplicationType.Unknown:
                default:
                    return "unknown";
            } //switch
        }


        /// <summary>
        /// removes a backslash from the end of the string
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
    } //class
} //namespace
