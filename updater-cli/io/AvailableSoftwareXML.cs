/*
    updater, command line interface
    Copyright (C) 2016  Dirk Stolle

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

using updater_cli.data;
using System.Collections.Generic;

namespace updater_cli.io
{
    public class AvailableSoftwareXML
    {
        /// <summary>
        /// name of the root element in the XML file
        /// </summary>
        private const string rootElementName = "softwarelist";


        /// <summary>
        /// tries to read AvailableSoftware elements from an XML file
        /// </summary>
        /// <param name="filename">path of the XML file</param>
        /// <param name="data">collection that will be used to save the elements that were read from the XML file</param>
        /// <returns>Returns true, if the read operation was successful.
        /// Returns false, if the read operation failed.</returns>
        public static bool read(string filename, ref List<AvailableSoftware> data)
        {
            var reader = new GenericXmlSerializer<AvailableSoftware>(rootElementName);
            bool result = reader.loadFromXml(filename, ref data);
            reader = null;
            return result;
        }


        /// <summary>
        /// tries to write a list of AvailableSoftware instances to an XML file
        /// </summary>
        /// <param name="filename">output path of the XML file</param>
        /// <param name="data">collection that shall be written to the XML file</param>
        /// <returns>Returns true, if the write operation was successful.
        /// Returns false, if the write operation failed.</returns>
        public static bool write(string filename, List<AvailableSoftware> data)
        {
            var writer = new GenericXmlSerializer<AvailableSoftware>(rootElementName);
            bool result = writer.saveToXml(filename, data);
            writer = null;
            return result;
        }
    } //class
} //namespace
