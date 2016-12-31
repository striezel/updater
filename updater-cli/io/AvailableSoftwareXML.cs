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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace updater_cli.io
{
    /// <summary>
    /// reads a list of available software from an XML file
    /// </summary>
    public class AvailableSoftwareXML
    {
        /// <summary>
        /// tries to read AvailableSoftware elements from an XML file
        /// </summary>
        /// <param name="filename">path of the XML file</param>
        /// <param name="data">collection that will be used to save the elements that were read from the XML file</param>
        /// <returns>Returns true, if the read operation was successful.
        /// Returns false, if the read operation failed.</returns>
        public static bool read(string filename, ref List<data.AvailableSoftware> data)
        {
            //Null, empty or whitespace strings are not a valid file name.
            if (string.IsNullOrWhiteSpace(filename))
                return false;
            //File has to exist, because we want to read from it.
            if (!File.Exists(filename))
                return false;

            data = new List<data.AvailableSoftware>();

            XmlReader reader = null;
            try
            {
                reader = XmlReader.Create(new StreamReader(filename, Encoding.UTF8, false));
            }
            catch (Exception)
            {
                //Something bad happened here. Time to exit.
                return false;
            }

            System.Xml.Serialization.XmlSerializer serializer = new System.Xml.Serialization.XmlSerializer(typeof(data.AvailableSoftware));
            try
            {
                reader.ReadStartElement("softwarelist");
            }
            catch (Exception)
            {
                reader.Close();
                reader = null;
                return false;
            }
            while (reader.Read())
            {
                if ((reader.Name == "available_software") && (reader.NodeType == XmlNodeType.Element))
                {
                    object obj = serializer.Deserialize(reader);
                    if (obj.GetType() == typeof(data.AvailableSoftware))
                    {
                        data.Add((data.AvailableSoftware)obj);
                    }
                    else
                    {
                        //wrong object type
                        reader.Close();
                        reader = null;
                        obj = null;
                        return false;
                    } //else
                } //if <available_software ....>
                else if (reader.Name == "softwarelist" && reader.NodeType == XmlNodeType.EndElement)
                {
                    break;
                }
                else
                {
                    return false;
                }
            } //while
            //read the end element
            bool success = false;
            try
            {
                reader.ReadEndElement();
                success = true;
            }
            catch
            {
                success = false;
            }
            reader.Close();
            reader = null;
            return success;
        }


        /// <summary>
        /// tries to write a list of AvailableSoftware instances to an XML file
        /// </summary>
        /// <param name="filename">output path of the XML file</param>
        /// <param name="data">collection that shall be written to the XML file</param>
        /// <returns>Returns true, if the write operation was successful.
        /// Returns false, if the write operation failed.</returns>
        public static bool write(string filename, List<data.AvailableSoftware> data)
        {
            //Null, empty or whitespace strings are not a valid file name.
            if (string.IsNullOrWhiteSpace(filename))
                return false;
            //List must not be null, because we need data from it.
            if (null == data)
                return false;

            XmlWriter writer = null;
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = Encoding.UTF8;
            settings.Indent = true;
            try
            {
                writer = XmlWriter.Create(filename, settings);
            }
            catch (Exception)
            {
                //Something bad happened here. Time to exit.
                return false;
            }

            System.Xml.Serialization.XmlSerializer serializer = new System.Xml.Serialization.XmlSerializer(typeof(data.AvailableSoftware));
            try
            {
                writer.WriteStartElement("softwarelist");
            }
            catch (Exception)
            {
                writer.Close();
                writer = null;
                return false;
            }
            //write data elements
            foreach (var item in data)
            {
                serializer.Serialize(writer, item);
            } //foreach
            //read the end element
            bool success = false;
            try
            {
                writer.WriteEndElement();
                success = true;
            }
            catch
            {
                success = false;
            }
            writer.Close();
            writer = null;
            return success;
        }
    } //class
} //namespace
