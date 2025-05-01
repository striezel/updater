﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9d1b25d58094e5da47faaf822c3e6e2b5e0f92fd376d1cc69a4fd9fa0d475ff4a129fb7115719016a3fc14522ea8f3264cfe9d4b36f01c0dd959f1455560eb85" },
                { "af", "2481b3793c1951ee588dae9904ee544a2ebafda9ea77810fb053cf840fbdede03c74b236617d7f9f60579462569f4558202e7c93a794a90a3476e8cbffe9b060" },
                { "an", "7b571c97d66268f24075c5e781f9b6f5e24d54d4a4839dac305829eb45396c9d3bb325353c0ceba3f8b8b8c03ef05d856f591adb7882cc7ce72d78be847e862c" },
                { "ar", "b61d8d907ab86025af181d4a2e05c049e5ab823e0f35ad02ba220696f594526572b9243e971110eb62454459e7a4864dadad479b2194ad3d30dbe624775a633d" },
                { "ast", "3227b905af5132327f16e971d6a0ccc0a2883d5584f49109a4efb3772cddb9b935aaecbfe09585ab5104735a3f7a6845cf1e837acf721144f0b07399f92ac040" },
                { "az", "535d68bdb830d0da34f1f93b2d3a2828de7c1bcbaae79c379677e177b8c75239d96202f6a1a9d70b49114406d7ad3e25f950b05d1b42effbe3c2b6d011ba4a80" },
                { "be", "53968d3b7461fe62b34a7278c462ae41feabc0706a64ee3cb6f66045a2bbbfccac14b5587bca6b4f8721bbd3201118ba4ddb64355045318644db1f4f05210954" },
                { "bg", "216a701cf07517f75d45c80b7a2c17c0362e7c493903bd6148749f7cee30edbe674c0db3647a27e8e818af8fa1b0baee42904b18fbc85261781f215c8b319025" },
                { "bn", "f3ba5724bbf2e041d93ee837eb0507849d8b805b1f38782f555e3c61fa1964bd4003c69e30b18cc39d8d9dbea9872b2fa0732bc9c0ce846c6f71f5598c7ea56c" },
                { "br", "e4e5779e7aa7b3c7e72887ce63c264895fd45d46594b59b48a8b33b3c8bca137ac738bb6400c671c7648b6e8907e502bb8acb3208abdd41b579dcfd9a7bef353" },
                { "bs", "53de9b2d96d274eece7286214accdafcda5d05fac3fdab69c85c176660972f592f8328592297aba1fdcaf9da43e9a000a2ab78d9dbda4a1b3239ae2a198a0d97" },
                { "ca", "6e8ef98d58bacbd437904e60642497afc07b0440e2788d89903f409c78432cdd1047011b948253a2f34021e2d7929c332ddca9a5ae69d90bc32ee9053b1e3ba7" },
                { "cak", "60b1897b7c952a7a50303db12fb06ee8b32c741b72819cc35324a6b5d8b4eb7eb9c120dfb687691e19fec510954ca6ca7c10855dbf2c049331a8fae6c1a358d1" },
                { "cs", "c2da8ee8a019009cf004e6238052b425a6c1faa2ae946529b04d2d3b3dbc99efa2754564e50d9d512af815a3aa400f7b0a8a83a99e59dea20591c77b7a04657e" },
                { "cy", "80093bc5fe931a3687d4ef9019be4c932839e07d22b3622a24aa6727f5cabec0a24b918b540b35e83c2b7876de3a4b148191a9b9bc63151540314c254180e722" },
                { "da", "e9bd1f36146a0db7c1111366b9bfb688b36f1f6df5891ddfcbe2ebca215cc4b9b34b2e83b3088eff93357e68dbf576f7ac9e8b6ae43e5dfbad18c76c647fac50" },
                { "de", "573067da53410d60d26e521cd07c5fbc153e4ab5ae6cfa9a48e630c3850e648fabc0f3dfa2332782becfb0ac21bf23278b63f856f513707cc1fc83a15914e4df" },
                { "dsb", "3d707ac8a395364ae7c20e2f6bd9f7f3dd44430d1b9d4f00162bc09b38bdeab8493620b1f3acbd0abe686f4f7eb74de2462dadf871824585c531ea6e5b4f4b09" },
                { "el", "2bc7baddf0e6582c3533087ab20b7d8a433b7ea294839f1217db9b58c2c115310bbae00825f6548f09c0a28b942efabf404a2a0c132f720f43fb26f069a12031" },
                { "en-CA", "22867cc0268d8caebc23b823cb33ba37bf6c171fa0b9b81e55ede089c03a38423859be7d6abee1a858015c35132a9e025f0470d4c2eb9c4a5947a6fc6f96ae35" },
                { "en-GB", "350bd1d690f2971ee392da947cc7860fb236dd207e574b1d8ef6d9fd34cd2f06c1bcd4e856fe11c18d7159505e1014c14a3aafe00a275b464dceaa9abf20b2b9" },
                { "en-US", "92ada2c9bdb51419682e5523dcf977191a660fbcdeefc9bc0a5d3d1515d5e70d2570e0f3a70d52fd8924f3279c7148fad8781eb6767be038d608d676b6923e6b" },
                { "eo", "4be8a1be39a777fedb8623f7d212069ea1a14edcdc6392c4e41b38cc45a0b234ec45130e9036785ff3a473f627bf8ed13040d036d9292a40ac7c4874e9b78d31" },
                { "es-AR", "012bfeb01d03fd51487975144500b6956a2812e99fe125f122ab531756616117210da9b86f6b82b89978cc1107840d7e69600ed8e3ff048d27535d549f91fa1e" },
                { "es-CL", "5bb33ea65654f6d88c5626937bf9921133434331808d85829a4893be753d383f77d6d12d607c8a5e3b26af699010d351b438142eaac1d844eb2162a0b9752bcf" },
                { "es-ES", "a805acf344f3ac0924c3d68b1cd4137ac2e2a40471a5c28ff1841fbaafd3fe23299576b3b2102604bb67f56a05edce6fcfa41a75cf32bf44e28df38c75132783" },
                { "es-MX", "8a7d24560f416b5ccf8ba712f6bcb0e0a109c33806f49eb9711463d186ccbb265b4e084ff0e1884e2fede299644075be44d083b69fe6f679978f1eb5c84e336d" },
                { "et", "8bf85556b42e84fe2129b10c1344aeae4e88bc74c5d700acca547465ea31b67207274447a44a9ce237d1117b7abb6e9e8a1507cd72d9476ec24eb315d3b9904d" },
                { "eu", "2b58547540c3b4d2ddbcafadcf8d26fe945042874d85fd525af2f4056847088705a4eb1435ff93cbafa1da60275f69f8efa3cbba3780deaff7fc563ea94d6f54" },
                { "fa", "723042117e75ba486668c071d52b68bddfa076ba88d66b2cbd9d946ae562460a9c8ecff74335bf542b8c38a74ff49b4519ba74c19b40bb48f8e366df70429a2b" },
                { "ff", "d807d950ba6cf2b03ac25d11a05ce6651b339c03027f2ec4eb664441bae0c13b7374a6bbebf94ad889030afdcb6ffe858e4666f90bed5f4694dcf92d083eb071" },
                { "fi", "6b6adac346a0ef3c150b20d03d97574e6208c9be891cabf0269e98350ec4b1726808fa3ce0eb9336e648678d1bae4120ade122d2d9ea03d03a3b35a8f1644d34" },
                { "fr", "42d88d8ed8f1e46a21366efe2a8846971f631e82ae84f6fc1dbf9f9574fecba15700e03d6c58f8073afde049be42359a5b10425ed0a84b3d4a840d8fd44a652a" },
                { "fur", "42e5ddacd2dbd0274dc62298348ba581ba802a9d16bd1be5aaa802ce2b10c2334accde1f47e00d87156d23c7cd02bd403430c738c602ca8b721dfe2a55fc9a7e" },
                { "fy-NL", "9caca017ea53f981f99932c197458790933294a7030a54709d040c8b3f9251d344df52ce141e63f89e207b39da62e764e6b8df4e3c22fef40310a026ac4ecaeb" },
                { "ga-IE", "e3ca69bb5c385c3823f207327083e0a3adbe9afa7df1468d9211eed8dc5c4846a7aa688725a1855fe306a61a4e4629a181bfa1ea4d539ba520ae2040349abd8e" },
                { "gd", "542a81a056b70fa973f4516d7ff2736be7900c05f8154f4f9a08a9de6f74c7bb0f8cd19abc53b43b393f435570f06569df53d62c53ed608ee795e17d09a4a422" },
                { "gl", "67cba8eb04216a5137c88ba22041aa6f86b56cd8ed50c20c1f256bad7da054a7154f1c4ba6c589bcd47bdef74ae5d9bc1649d8f9ebfc6ec726f2256eca8b9a0a" },
                { "gn", "6d07c940ac98ed5a51d5ae22690ac7b04b97f6f34c5d943c9f4ccf88f4f0fe3c11266116bc30063d37c3b4a5f3514006c1e66c6fbc172cabb8972298898bad37" },
                { "gu-IN", "ba641570616f5c8761ad2cf9b017cd2a71608f811810475a726efd4e577fa2f113c7dc3bb47730386009320bcf80f63f51299ee05df52a9ecac5091b29b2ce55" },
                { "he", "f36e6b18baa6479b591bc4aec165a8eacab15eb4c85ffa018834fa7898cd104f9b3a50c6c791e7ead7123015109049f8be1b8f4e3b0256e75f25e9456f43ea99" },
                { "hi-IN", "a58b796ffbb96980d2b9e41bfd00c4fe243971248c139d7018065fb1af5fb2b83afe466d55d5dd7fb88b79ea2193fd93ac05962b8ddd04116435b1eb71fd3360" },
                { "hr", "acea31fb1737d1d28ffe53e1af5c44efb636c641c6fbe7689129879bc78dae1915cc7c55d025d7a77b81ee14f92a8be1104ac6ce0d79263aa61e6eb10f157a53" },
                { "hsb", "7841f743cdc1f3aea02a442a76c5b05ca6b0e7aad3af4209cd29b27b6c8c9b6107a2fb000986e9d6e36f162c6b1b92ac814d6d6049878bf9b290d96ad610c47b" },
                { "hu", "493a087b63971196fb8f6e2f81a764295c6a11cb77885c98d720ee343e87b9080651d2068590906cd34443b4cd6c250244aa9bf9c1d6f129e56c868cdef3c8b5" },
                { "hy-AM", "989b396fa885e289b92d12a1411dd7d70a589872b418b4453e6799434bca6112198e76807da9467832ebc0bcef9ddfb800af6a2cc1ae9911af519968b9adc2fc" },
                { "ia", "47fa5ec0ed988b2a94ab2d83516570235396ced0d7fd624f29efa659ba3091122c5a43f64701992a71614d637f9e124fb545f079c0be901a9200412b7379fe64" },
                { "id", "1ea629bf0be4d7e0aba2c43287a87fc98ef9dbb4d7626743e56e93fcaf7aa8cbed7891210d0505f4ffa1ad553d013cab65911a5f78d4d92d3bcaa9c3a3753ae8" },
                { "is", "e4c91012005e1edb52fefdc6935d64daa493a75cc3e9e3aae3474f0fa23d68061c2247471ac47a64035f7cf07cb4236259085ab2770406ce925f7b0a3a56d95c" },
                { "it", "ec15b412186fbe593b553a628d39f4c48e81e3b1ab12c5f519310f520bb6766cc67c12aeffa855333f27daa76986a53d3e00cc04ed266a97aedbaf4d7a9f6bbe" },
                { "ja", "4e3f18035a51a262d71ef10613ee395fa275c02a12812a338505f9a2923b32c0fb59e5b6dcbee5e351c0e43106cc7fbf0e714c9f4b6baf72dacf262991417c85" },
                { "ka", "e6389e4110e33363b23ac1f84ad094a925d6a9880ce438eaf78c8c1fe3fdc9852132b5eb17a9e0800979d698865d587ae6128b1c4ba32c793c6e29d276362adf" },
                { "kab", "2b0a22f92b85a81ad31b96307f02be3b15bedf05f9cf97901c4393743a3d8f1b29815d1705338c86021da3248958b9c1b0df794ee8cccf0f546b31b982d8e172" },
                { "kk", "9d8143a99291816c85b3da420de1c08eaa94d7e9832a060e7c7e1ab957df612266a7c74deb941915fdcab69bb3f9dbfa0fd987841393363f5fdc978c84e76a84" },
                { "km", "1c7dd86d87882aaf16929447f0da1c1c109f17c04a9826a69ef11653053b255ffe564e4f791f8e29f553e46fdac204119aaad75e4f71e5fcfd65b380499a47bc" },
                { "kn", "ddd13a28d6c79490709208fa477e9e3662e5e421209d1e2b995dd17d5358f4b8cc9697c95c5226daa09e15983d7e68d12f9f18c9a3ffabd49641ac715c35d2d2" },
                { "ko", "fe9461fae4d4e81c611a6b9e0c9a03b0cbe4c43d4cf6d1cb7ac59ab05a8c661d912cc59e45945475a6dc9fe63d2cbf2a978b62ea55e2a59347b38353efc509c3" },
                { "lij", "df36249795c6b8db5460930056066721ed2f6730915358bba96741dd00d941c0c5d5c941d140042d880dda9635a60fd25ff56862017113a13a34247dc80693e8" },
                { "lt", "689e81c0b1d1ea55d297e7a504e8750f1f724ea33fe72c134ef1f5f8579a97497f0f42eb70c516be0c9361fee1b7c00deddc42cf2499d5ec2682689b693c4e80" },
                { "lv", "66a16c60f5f1cd02afbe2bc890d6aa8b8e6ff9b3e6f6c444269727468a963930b67303e1b11e64a60f09a32efc0b2fefb9458d78a5501a452ef5b4e96898c84e" },
                { "mk", "8b4c9eb2f2094a26e10ee73603eaefd47f4baf617d6a29e4cf201154660c839b82f6b0b19bfb5b6fd2feba5616b1e38c76eedec561638ee4f286ddcb4a55278c" },
                { "mr", "b7aa0733d17ca3219155a0cb25f7f81283115f2d62ff2d56b0cae720bb4c96167b72fb357f7056a332e776c02e863b1700d714ee501ade204a1d3094f74d9e76" },
                { "ms", "01f7c422d37551563dc8b4576f4c73d07b9405a981560983d97d50f2791a0c642760980f9ac70439d0dcbc11109a75b7452fcac16c0029885a80839669e0d7e5" },
                { "my", "50f6067b834fc54724baea00501d53cb8a7b5766ff14f1dd4871c21e8696965a4d5ef228e77f225007820fa585e1b3dc03a11cef4db1f8e8dbb55cf37325b73f" },
                { "nb-NO", "0b6755584f7d73c1bc73506b55c71af98c4298a6c44e3a6481b133814231cd2b4ddb07bacf67247ad7fbb8be0c24d97887c043d9ec690b4113fb25c6956d2a7f" },
                { "ne-NP", "eb17a9a6356d4e69eb03ce6f535d14210ee19e6617a1979e1dafb234bb93985167b0b56b05812946bc22e76fb7194fdd91b7f49b07f1cb61fb8ceaa7f05fc3eb" },
                { "nl", "c17a6c5f62395bc0b64f2530742e4d176088b269c7f02ccee4c00901934f2ce9e8db646819f8870ef87eaee8282f726dabb70834bd427798640f469be5e711f6" },
                { "nn-NO", "9a9663797496864be182e771dd81e533397f1e78231593dc8ddc3285e7ef028dc5ca076ccf9e1c6b43b9e7b78e2d24a093c9b2ee5b25f57a50b7957336a9b261" },
                { "oc", "a87e8a0f58cecbee6808e8309cb2d64abc6e00c6fa3e0d453635b8f47a08075bb81f554058e49859dfdf2dbfc08509d0b9ae68774f401d0506877b5bde2d82d2" },
                { "pa-IN", "e7411d3fd857d036687cdb2a2964beef0c53e1e2dcfe29f3f67031834776ebf785a0740e6b839be089c3162fd9319a4265dc5979f078614f52d9b76da3583cea" },
                { "pl", "bb4bb00edc90b7983b84452b4559d0b20e6a998435db7aae5f29e4de0e8b1c731baf72852dac5455829d7f49b2f9f58f0a0d9d86405a84176b1b78c69d95a579" },
                { "pt-BR", "63f7f4ed52f90e11d2bc8847d20d14cc8b1275bdd9f55a06ce3d4344dcac329077f269b494235ba6e7c5b9f7b7b922e819b0ac67d4c81dd1b7ff685bd6677418" },
                { "pt-PT", "98b538d2ba6006f8fa87704d4dcb7155dfa19132fee17a26d4f5b8fdd186cc9f5b93d3fd320863b0b459a33f947db44bbea5a2e3c681b132afdd8c8ced67bdf6" },
                { "rm", "0c0b8be3af102a24546f0a680851b5773880b07836efe1b2056b98e30925f01115a909105b6014b905d7933cb8c0fb67f4f1b719731fb05388d3272e7a497310" },
                { "ro", "a660e907e521cd32578df67367b4f168edda8e13265715103e12a04559d9d97fcee28d7509c6838c7cf772ba9229583d5507b67b8993816c0cba134eb154429a" },
                { "ru", "1a98f71588dd3ba6febf03b47f31cf85500a6ebcc7611522234de912fd12c83a751b197f94beb50465c526499530635f1c973f1b6a66d5bb837af7d8664c2fab" },
                { "sat", "15fcad5d5cf5bd667ad72d8d25722e0c60eb1276a23cd36ef76ffb5c279569984d168194515fc368d8e7439620c5efdd4f85c9800740961260600f5a95e00ecc" },
                { "sc", "524633ff66c9e6bd0af18efee6f1d03104480cb1e35374837136ae8e29d7e153ebec22c2a6f1351d2ac044f3222266729426a420cd9f1db05e8179222a2fb2a2" },
                { "sco", "cfc39da78f6e20784a67e063e15eb4d607ab120b90de6bf79a8f9a8ef4847d59402011d9c04a656e595327f330a301f6b3895b126aeaf849fe4c14701cbc86a6" },
                { "si", "31103bb04610cd8e4b6526eee06d84d65565265555e37c7d63da4d225bdd4e49a7bf8ec47abcdc8963805374c1f3e458311fae93b5b4a65047d5849ac68fa113" },
                { "sk", "2bba7fdc4de26bfc235f0fb656f775441f719439c56e835e26882d039137c373713e3c562420eb72884bb703b023920e5b709d7bb88b21dcc61f37c4f571f53a" },
                { "skr", "c4f237b4dbe78d4e2f10d2dfcdc1f447b137f17b080406b6fbefae9f946754f62a156b1a481f7b752133cf71c5d5dca475e382b96e283975760502bcd7481d79" },
                { "sl", "1458777bd4ab8be72db39572910a7040b98c1f75f4f8e21c336de335faab8276f2fb8f42391fcc04a1b0f67514841e2e35b50709d3c8dc7180bf3eb370ab4752" },
                { "son", "ff26897dfdcbbcd0cc156664d438348a3cf7027b051d268321eabd99b6f4662aab59d9adaa3c4dc646dc11e23815ac439167e7a93830e790c86411284910ffcb" },
                { "sq", "1119c6a076f9fdd711eede0dd7a2bacb4b318efab6769c8e6f4d58f843f81dae6d1224252e60777e9ff6adb49995715f187392900e5aa28961381734e77fd842" },
                { "sr", "d31bdee5662e0aefb0ad3092747803a90cde9c4570f237b2eabc511aba239600f57050c1a483e53d6306decf90d780846b65a8efe903c3846020343a62b7aad7" },
                { "sv-SE", "efd18aeb45a175217f86865d0c505e492af6ef35a5f595112cd4efdf17dc84721889f184ead29db516f1d6da96f1fc260b1e5dcc962d3ef1ca7d939f5a4e92db" },
                { "szl", "ae4d440823eb8fc9018d3e6b550c4d28df570cfa2f6bc15a2ea22bea88373e830a631cc1fa9b19f3ae7955e76cd0f7f59fb76a4f8d5982a1def7d36fbe7d09df" },
                { "ta", "9339db60ad63435fc1a1ee101fe9ea478365fee98d0d7bbec5193f846393da235c9688def39c1cb5ed9555b20e5d243a3fe4efeeb842afad4bef9fa6a7dac2ef" },
                { "te", "d791f5e43e4abad81e667eebd13d969d0bb7e0e1953b94e54e58b42c33ddd6a78f5de88afad74769d637ae370cfc2ee27fab0b6bfbcf139624eca0ca591adbb7" },
                { "tg", "e32f97652563966db52399a52695f3e0f59f7d23ce5d10778a536a6ed6a06bee2306e591c93a472b576a07cae186980fe5e76ff465d66aa915657ec6395b750f" },
                { "th", "85296d2bc5e3a392791d2f85486334362a6c716a492d9bd99a6afe5ee84da9096cd28a30696a9b936464d1ab145afa07d02711eb454c1400166be6ec4bf96daf" },
                { "tl", "ee0c1a5883afdadb91dcf95bb0e4cec0ee90018dfa6513633ef8b0f76ec73c4419bbe3f28018ec4af959ccd3910dc5a0c4dc5c0334d3db0c7d9ff99946fd09f6" },
                { "tr", "0f20d33e4bdb09573be2175354ff930bab446e9fd69b0ae64b3ba3c05ec6ceef3d030fcd8cccc3a6aa7ae00a5ee3221e76b224a739a5cdc89d59d5fceb405279" },
                { "trs", "fca6d8cbd4174ffa2b3037cc96375fdcbb0129f710208f90c240cd3ee57b5fbc2c4477c343b9223355de50df425ee2f5f42d40ef5b11e6626f1464beff4f1b70" },
                { "uk", "773ca086f12c53ddf47cedb2e4feba5665af0b81465b0e42e89efcaae0737fcdfa375fd0287861a907bd042d16b6f50067b202304c1236298a252dfc93e4aa35" },
                { "ur", "a4f4ea370914726cc0dd73026b54c22cb6024fb7ee9313eaa8bc1b85f3a039d99b09e7f284c5345ab72e4e783a05d2247d23642326e3d551f93011635336c9c2" },
                { "uz", "86643acdf23000c86e304c04545c77c69128bb4729a193f98f21e1e64d77ebe0d77145810b7d712e57882a61b315b4a538344cb7410001dc782bc3cfadd726dc" },
                { "vi", "3e7bd2a2e380519b98b2ef462d3708f027942b8957f50d4a9724a8f7cff8eb7de9535535a4e54321a4f918d34776e3bfc69e873ec7432d2868d0b65756603ab5" },
                { "xh", "9edcd1eb32171dff4a3ce23135855391c883a409b8094f58752eb3d2b8252dd8656d3cd7ab9b3cc0a8294f92ab6fab5dc8345ca3ecd67494cbe9542d7319a093" },
                { "zh-CN", "b6f73930d49914f1b97dc44b6dd5a9b75e0f066e65ddebfabd84f6e4ff94ae119034d1b2d7833d5392a6f632a1bc61088a319fc980ceafaf0602918f66975cb6" },
                { "zh-TW", "cedac9ced4c664e73922323a90f28170ffee46dbb309a85b8d804ba93229199206b50099d2c95f2287cbe72bb0e7c3d1ae82ad336562c22fdb27cefb90deca13" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4108dec10833e40770ec951c5524a00c906dea984e26599c5f1960a5a6145f3eaa4e28c0b5d492c265907a8bf768f3e1bf4d1e9d2ba9299ca23bf71983b99b12" },
                { "af", "751e8211ffee12ba2c8f55cb528bb881ed3f1bc6763d927e3c54cf581930d4c24732b6a8efb94fd48b18c820943c967c487241a44c300b4727e513c0cfc3160d" },
                { "an", "267e14ce0401f3b628fceef01c67b66af8dafe49901a8969f7d14e0ffd0895717b9fb9c3fe9092dedfa0f5e9859175265922f9ea34f23d61bb1c8d416a74e7e4" },
                { "ar", "f2038b833cca143b7018f0d446c0976683e972491bd63fca87cd20d7b477b4e43437669596a28a2a1bdf4470afb8b5f71276f0fe0d8c69d00431a0a7ba831947" },
                { "ast", "a40c98b5f04f24c0ce0f5906be501cdb5cb77e3baa073fb8d192fa5cc3f8fd584924c79f893259882898d6e28bec1ac81103ae332eae19b7020fe48c87dd0ed6" },
                { "az", "d4b3342bd8d58ca904a2a3f233875bae244174b821eb1cd089b669efbf654804577d173903ecded0f5d2997dcabb25a2348f9bca4638de414b5bfaef6259afce" },
                { "be", "6139c05a2cd6503d6ec1304d8c6cb74b21c83f8598e5987914d2c48c13ff432cf61b6d3a3366188db850d2f3f74c6a74446c3deb1ffb1b642ab5e6a8908f19b7" },
                { "bg", "7f753dfe5aa8b6dca23d2b0aa495ecf50cb871db852cd5e3298b44eb5d106b91176482913bb6d321dd51bc805ec2a9576b467ddc3ab42e7bb64dd715ca2a4b88" },
                { "bn", "829ebedb13b290fe2a948f380ea541f25f23f8e0d8d5630a5c5e564d634eb103df179359f661d0b9ae4b29f9814d2db9af545676ef5d1e8eb49894b6a9ab1b8c" },
                { "br", "dad6d856edcc7f062a383de21787278ab243e26fd4223629789a130793269aea9e085fa639007d370e14dfdc66d42c6fb56e2cb1f700516cf027594a54805812" },
                { "bs", "5d00a2a9698eb6e9fb619791c179bd512b359d1b61bac31f062a5c62b578dec8b9a1ba103c899b6d33d4f12097d658e705c8d2a20796837477cccc54bb375b2e" },
                { "ca", "b9dced7a63b760adf8622187ad4c0c214cfaed61fe8602462b2b8071a276ebbe8721fe074d9e2de4383eb89b7c5464ec1ca22a33e59228b304b9900bd55471bd" },
                { "cak", "76b9445c7a4ea45af2bdeb1b4be68a6b04598813dc37ae6c98f632ba8269ea97718a2238738e5b907b74a584310f6a6524d0e3594b5a3fae39b85b0fe42d3a93" },
                { "cs", "a2cc972b34d4e17a514fc716f5ee04258e8f4ddcb48998db73eb4b96eb49c1334092f886cccbaa25df19552dad7f829f37452fc5770ff7774a4c2c9fdb349ab6" },
                { "cy", "cef1db6c63868d416bc630fbefa7c05692109afd2b20bb0ca9eefcf47fbdeff1565aac865008baf8b50db12a9dca2d42ecada5d1cb3a909c61e12c68b295a905" },
                { "da", "a143ca3251046bac6a695b04008998cd9ec1f46144181269121566e8befa3042d3f081f2d641a07a8620946f172a4bca45dd306753ad2feb0a711d4514129363" },
                { "de", "6c6512d737c03b2e340164ce8e050bdebb83c3f99d53578c444859a3532ce31960e616b5d765fbd4be08c9ea25987e8b04bbceb8043554a19495d565295994d7" },
                { "dsb", "0a7bd3f48ec8760e5f6bbdc21aff30e70faa7a237ea00a7fca392516d163f5b6b378ed23c92131b9e12e32636d578d86e1fce311b3962401a888f3f30883994e" },
                { "el", "086ea1bc6365fc8c63042094d633ed0a713f5e3ac194d40eddce282025d54b4ec8776cc6a7ed9a9af22857b0719a8732c6365b052796a9c4bfe7ed2533f3dabb" },
                { "en-CA", "751c24936e460526b29681c86dbdd2f90539544fc8c885a396fc73bf4e7ac223a0ec9714d9e5d7e640862c31375c4aa4947f611aaefd657a7e42cbb82e7fc852" },
                { "en-GB", "feb3bafffef3e609dbdcbd72706e4e4b537aaff593df5413cd80ac91296491766698aa194b4b358055dd88ea51741cf3947bc399f1a8ddc21c3e5147918eae50" },
                { "en-US", "8fdf13df9954e0fc5bb59880be85d0e87530c2aee732ea640279a8b4be5719256a95f0ee7fb60d26d1891a969ef37f634fb87a0405b099e5e2e6ea87a9f586eb" },
                { "eo", "c995f1c74b490f06cd68d759d0f26561504e60f01fbbf471b1fcc8a08ef257b99eb2c6d607991fc32807c0914989a2f106ed3428254c21aa5ce0ef1dc9ce285f" },
                { "es-AR", "c64d0f6eb512057477b3bfbd6d840aa44fbce5f6bae95e18260237179d14e7eb07c26100d87115319037e667ee302b6b66b8d85ea2817f8b2a4a6c32c50ba0e5" },
                { "es-CL", "510fe1d4b891678c74919740484c5cfb9e990107983197453b4a088158398d1d00cb3eb3ace9e6ccb2843721cd556441fe749b2dba0e4cd7befc8f9022182146" },
                { "es-ES", "2516a6d2bc992dc2da3ff0b8d06316e1e43bf4eb43450cb01b1f7fd52f8fa4f1d08b9edad55d394bd1bd6f77dc7959905f0a1b5098df7408efca73855b5aaad5" },
                { "es-MX", "4eb5be214bbf05e65db02b7dc27e810acd1359d9d640a4b4757e338fe35a544b9ebac43774456e29bca15f012e78b8a9b8a560a72c54ac2fbeafc14dca2362ba" },
                { "et", "44402db64a0ca31d559a0e4385a3f8bf7d9bba81aa870a3d094b4a180f593644d0ed44ed7cbeeeb45464030796f8a85069d007cb8d930e8f88799100d81bd2a7" },
                { "eu", "fdbbdf99845eae891554ffdd119bc55499eb42fef4f93b11ce3ef67eda4a1b6c6e4dfaecba2bc07e6b8e6b6f1f51a7d29b653a3ee117084ee93fc508e054ff65" },
                { "fa", "ba8e4f327aa858bf619b355d2c88f8ae0934476411f12702e88bce389ac0b2f72cfcd92dd77ae02b10686a1b7b954b71e3df927d49d43f37f4a65866b9a2703d" },
                { "ff", "6d2d3af55ec19c798fda2fc31227aaf3f8d480c99ecc3c56e0dbf368fb8872cd68169a10de21eccbbfd94b5b8c8226db6f0db904bdf539a88faaeb66e99320aa" },
                { "fi", "148bd08f1ddb0321237a912b0687e17d157137b40ef0ca39ca0804e25a6ca5c8dcfc66465fa867f193dd89135d6b189326fdaeed1efe521f80b6956ddce04921" },
                { "fr", "79a336b8324fd560055d43ff4a45d45977c6e0ca04c410529c4e0d2a39fc1eac1965c43afedb5f072920a4ec3a9aca05959e71f68271b709563c86b04f077ce6" },
                { "fur", "60b633f39cf48eccd859d37c20726307bd4d42359a4bbbe9cbc920b7bbd575db0849d456cbbe7f31ffba9d9c3c4703a4419a8aa399a1d522cefdcceb88bfc233" },
                { "fy-NL", "9d6165c0a1eda7aa7d18eba4a21be88972db447885a442b7d0b8d0f50a80dc3007b07b9f305a7ceb8a5f38905842e5144d270f756a95cbd44c8f3084e688103e" },
                { "ga-IE", "1a74004af6632bc6903814a84e490bf9fef89359f1c0774241e1094a948650c3a763d1ffcfd29deda84de1b3bdf4eefcd6a14e3ce0bd6c87f2c4edc35ea42add" },
                { "gd", "e433299fa2105bd667555b2e4586d48698e7b8172c09f6d2d6bc679feb928a5d3b9336cfcca1ebce1283cf12c859f0bc3c80cad53447a7148962b351c4d1e50e" },
                { "gl", "8d6cd50770cf9872508163aec4236268de1cd580e1cc3cf193c7e60f2c3a178fd4ea4829d9b32e2ab35143e7057e29841b567a8185eedccc8cdf612938d7be79" },
                { "gn", "4f4964d7f0c97e49fddf21e83ea28938eb52801a376778d2aa8b72372b885d10ef8f3a773a7c24da8d511385a3772d6397f1dc16f064fc43f5422b7c899c5bc1" },
                { "gu-IN", "a6f9e218c54340f15487e822e426c5060f0b8e7be00ab659719a70625139856521e39cc0f43f7da9e9cdbc9d9b57f6909aaca7ba670e257b9b6f49681dbc8e9f" },
                { "he", "51cc7f74438a075def3d4838b2d9d8d4636cd65845cfa8e7810227c83c35d2ae742c3f951262ff8a9e38e1788d60e7d6ffc0ea009bc93f238b6263f701f602ee" },
                { "hi-IN", "553037dd2259d69743e24feeaa5d888fb552a4943affdb481a06c341930c0a2f6639161329961f6082611580947b0e1eb42746286c49e9b892cb69483c989a2b" },
                { "hr", "14d5803622ca085d43afa01204867dd220e92944f6e359b62aab9e6c4996bd4cd7f346a01e8fc4671d3dbc697ec914397cb950a8d4db55adb8b432b8b5024a0c" },
                { "hsb", "b1501f3e8703a81589ce2d1f0bf0f9f2374c77cf8ed9e0da18aaaf8157d6ee383dc44c67110d1e5530725f6df85409270be14a3e834e0ea8ace6e2098fa62809" },
                { "hu", "61ac1cb142d5a561a82ef148deb27ae91f11d3e351a31d38f282f14d81b8391c00bd5b087a74a559f36ca664c375aac4c159c20413e9199857ded857f0226988" },
                { "hy-AM", "fe54656ed5bd17530b932d141b766c891aa93a5d942732fafe132a405e60ce09fecc756cff374d2291cb2efd8e835b9094bcffd70a82726e822f2b07bf61af77" },
                { "ia", "cad4c289a1e1ce36019983e46d7d8ff351d92ef22763c54eb142af9f17657877d860137c27c681509180e9216032b3501df7ea2c28c04a44bbf40bdd86cc1388" },
                { "id", "07baf61edbc1ec94916c9a8ad6b377cad73068bc5a4c9d87917577eca85053aab7edb839f7cba4ef2c7f4199c29d04da4df16ec1bade30c0aa785ac9167638f8" },
                { "is", "2a7385be3a49aba8a22d4a8383c345d6cfa540bef66039ecbe0a8a6c4df56ae6c6d799f928ab26beca4bd211a3b0c190daa409c3af7f9d029f299509958d89ec" },
                { "it", "862d52d17003e85aa8a2c414d9e53a6b648398a42f56460d146c9e33c2b2c00519173ab82b7f3c40a09a314999dfe344c2a0b10ecb2ef75529a3f2a66789f008" },
                { "ja", "7699fda69ee71a9f7e84641ac47a50ea15e8d45e52c8033a1e7591973458016017f69d718fc9ce68b87712a814b34b8e6fed835f738ed79c61c41f2c1313ce62" },
                { "ka", "c3dafb6fb46f621a2bfdcb240b58382a9cdd3d2190da6f20594bd40ac4fc455ddb4f255d9eaef90e0b8b3c0453750e6ed38a974124edad9f4d8dc0fc63a53db0" },
                { "kab", "c8601dd8edad526b99f1fefe3cd2f8d1e7f16f6b3f60bddae047af203adfb69b0ca95f5554fb4a4b0bc0a188782e527dac25d79fdb35e9e490df5983c1e9b01a" },
                { "kk", "cbf5f702d01bbacf1edc7ea13f3c9c47b651b0240e86c58e07f3dd0fb61ff7e725a7a4d294b74f67fe4ffdcbd14cfad6f91ac93dbf62d987f27c99cbe99ebc25" },
                { "km", "57ba095829045d036e0c1868385ee6999af40494937a8f060b5f2ce421369b1082eabc1236893e18664827b3a238990c78c25c4fb927fc03c69019ee0aa2366c" },
                { "kn", "149378a6abdae2a634388f0b6f7117bb5464039877f42a8da3809b8f2bbeb687f208ba9d7ecde141ee83580a3cd96512faae4c117356ae3f7a4ab29a21a71ae1" },
                { "ko", "696c5eafa7057bd6614e50df9779af7061d87599c57091d84df17dd39cc3ef9b9c836478343362a3a9250f667883b2821baea721ec95b4e4b47e23699a9fb707" },
                { "lij", "f633469d525fbe314468f5b2961dd07961810b927e14df7fc03d36fada431097f2919b57f092e71b840877f1f84a7e10dd782fc06fc91f3ed24406b5ebc71793" },
                { "lt", "260dc238473129b4ff9f5703770016515f77da2c68f4c18d847e2f0d0b4ed5ebde4542dd433fe89850b19311091468e298afe567632f5a10df29bf5de587b183" },
                { "lv", "df34eaee565127dc1ecb02444a24cfd9ece402ca075f6a5ba28d1798f03e186ebfe496629fcfe0c55d979b47c3d0287d1157015859f19f1675ae0a6635dd2938" },
                { "mk", "e83a5ba396c030cac97acb51d7e530c2ca0d424d3a02181ed3a1978b64022e7280e488c1ecf3ef19fcb0c4fd331d5ee0a1e0ed80632d3793913571a6092aae57" },
                { "mr", "1ef9c5270c0f81d8df8a8766712fb5d37f645e2d5c7d7061954397da25102e24453bfac1a6c1e2e1f744f935f764df30601758ac969435b26be9fe4a5f7ee7b7" },
                { "ms", "41daa3d2eb26bb3e9e04c46207e3183ebc663aa81c6dea94d8334b3df2fa9ce51cfb69b1316dba5c76a8ea2cfae01863bf860b1a4ce5a5180130264a5a437da5" },
                { "my", "64d4be3695e93b8f4818d016518cbbc28b3a9cd46e2b46f0c1dcf1d931155b401e6c4b2d49d30daf503d56e05b8428ccccc78103e018fe9afc00744011bb5c4c" },
                { "nb-NO", "21b0c318be65abd9ecee938e6ade958930b9634528fa2c7006fc1e92729c96ae881fc01ac9e3965d835e33ac0bf57ccba5ba97ec3d09de629bb784b7971e0b74" },
                { "ne-NP", "f3046f0c03cadeec346409ad3b21fc99898aad8c27542da53296f8f50e633f45966975f27b22b8e0cf0d0cf6b4b009a5c1e8eb7b8dc396bd4199c6e8a9f9e58a" },
                { "nl", "0be257ddb3139b12299b5b97b980addafab00181082916ae4f7b0c950f341c0531c634f9c24f2bfc3bde78bf1dff945e066b807e24cf58c4d2994459f9c28a0d" },
                { "nn-NO", "3664b3c47708561957f9a1fa1424228592287ca2b29b7e427078ca936484f0437ab8a80ac664baabe6c98d473ca5648bda4e3062936ee87f963ad814892b08e7" },
                { "oc", "cb5e42e35bd36ef8a8c2eb3f2788c5834187b379907378188dd5ff9681fcedc2d6912ba4f5183c38c53b0dc276406ffa32a932405de1a59a70b86979b144fba5" },
                { "pa-IN", "2046875f9fd438ed61ca81950784d2e871449f23c86773391834a845421d89b2603f73bce991a51af1762c4906a1ddb30c12f0d53628cbe83743a9e0051f5389" },
                { "pl", "ba47fe773eb8c54225d7218e3fd5c6a2841930ae319874f260f7513eec987f28f981916417697c349b8ee9ec88cd16e46ae5a8ecc8101d45f4e5c05d7bc007a4" },
                { "pt-BR", "0acacb32412c3ad0bcd7babf6e66f18792aae4aa7cb3613a3249005feacef82470e8b1da34b34e7c0cdf6f779fd789b7947aca583f7a6bfc619ae6f22954df44" },
                { "pt-PT", "2032b059de8c47b93e45ef4542fd8a82158865b0c8c4731b7bfc4ab422975a6be1d0c16261c2711ce3281ae5dddd5a599faef870834792996ce8742209b4e8d5" },
                { "rm", "2359a1d8a0615f6854cdda43dcbad029e2142ea6a3dff23870b7976edb16213c68d9b116cced6a55100ba0b5961cec721ee36306782187a7225cb7d285291bc2" },
                { "ro", "9d4301cef55184a47b50c3763ac6b7dc13482c25ef00fd8f5d906c7e5286d474ae936230040963710c3b0ce21ebc45dad985b466c631fd8fa310a34fa7139af5" },
                { "ru", "2e41f8e2f576eea00ee5b4ef6a30df92ea5e05b834a987fa3a3f5c66527b4140f28a3c2d9ed358dbcf5d9e3a817a40faf887bb7fed0e07ee8e5c4c676a3127e3" },
                { "sat", "c182e477a786774e33e36ae75c824152ff432422f6de6bc51b3be49d02c40920614634ba94d10b30474c9bcb6719908c3400c4d2afb2727944663f3c312dc1a8" },
                { "sc", "3a2af14787363e1bd817ea3a5fab0b6fbf9c2a3dc50165b99457ab09ab1f3ee79ce128d1265fde32928cee518979a04e9bd75e55307bb9a735712b3ea95af56f" },
                { "sco", "dc5f1125050de71033424a775461dd31115cd11dd0c7e3d38b1c950da17fa02dc5480a84121a4791ff0be423b0e33043b6f22899a1c362f4fdf47d8354ee2f52" },
                { "si", "f71b81d9930aab43a7f20eea35f601b696a96a2e5048be3a25323d7dc56e6986730533d4e78e2b41b947c3f51a9fec12845dfe2f6efa46a843ba833fa57ec7ac" },
                { "sk", "b579f898484f1c20f2572040737a672692cc6750383c6087b480cee79ed96e51893181497a2ee918bebd70be38caa3f6eafc9b58c4001419ec61e51a0ec8d9c1" },
                { "skr", "ad71deb1922fe433af2b455b1e44e4a17c42b3473117c6afd2ad8189cef51a890a0ab49a37618236a60c9be6a6bb83756becc9663bb42034708032ec44948dbb" },
                { "sl", "8884b56d21ddd68f8545d17756c0579091710ece80ae467a3ba3c7dfbd9880271b10fe1d30b108c238e5616828bb4328cdf3d5cd506d868a45379e460aff5abb" },
                { "son", "6fc4901c9645118eae66f82c01b9d0753b9e93ae58d46bfca13fc553b54f0d2c5062e55c9d54a4d788f17a030bbc0878b1f58b8300b88a1dcee010c10a4e2c86" },
                { "sq", "c514cd01ea4fd78538ad707727c1d4dceacc2093f5043b02daddfcf74faf385973862fa475154d93ec18ed0e660688ff69879a6e1ca3d4bc071cd8dc053c5829" },
                { "sr", "738694f25aaa5bfdc9dbc78ecf14bf747bb2f4c2e014c26a1558bdf27b33b7888ac721546f40fcabba1c9ee8f6bf9ec75953076968775298c635c918f81cf420" },
                { "sv-SE", "10b4e0b6e8398d4532881a765ff29b76907909118cfdef7de7e877abb737615f5870b6c414e553b703bac15f599facb6af54821743a9511f7e973ec14f82aa31" },
                { "szl", "dc2930f72302666b9ade88a65dffb077c2ef641e63c75769abec8fcbec965ba0802d346ff787af6cf42d0d18b8b71e5421be49cf3b4fefb8b6562e685e286f51" },
                { "ta", "7648bbc4ff0f4fef5d1a1b00906b4226be375fe364e7ec8c2966aea8ab97aa7e04198ebfa366ed6a9ec49e0eee24071b83ac4531f0cb463da20c21dd7b9fe6d6" },
                { "te", "4861d9d87fe52a429351963ec6fae63b7f07709d25a11dc094f6bfc1ba6a3a785d2c9f234ae5c9a537bca90bc6cdd55b431ca75020ad96ffce4d97956c09d4b4" },
                { "tg", "6535168675354649ac020e06cb9449a249e281501a4d642b0a6777a7b243a022cac2da7c68d72ec5b1046817b93c98e19366bed04c289d1a0bf17d881d3c9612" },
                { "th", "85ac27ccea9d7fdf8e398a32edd3585100f41eb7deadfc4cc39f812cadb22118d4115f81670eeb69ba6dd357f85e64a4d3249d8a3edfe3c8c80a4ace4d54764f" },
                { "tl", "d46ffe8950c0b34d5b64c84099323ba2a7acd55f275becaafec46ecbbe332965a0f02a225f4b9490e5f05fefb56ad0cc4af01f4ea5d7b6fbb8be83e797d07dee" },
                { "tr", "dec1f468e36b97bf729b1537cae2f4d0f2fbb266decc67e39ea450635aa9c6cca9a2cc072793bca9a6a832bed0bdac57003f849ec5eed983f42ce6dfcfe94754" },
                { "trs", "c821b10c947ea61d58cd8d802590811306c58eaac0db5b62a9770ce7f322762bf25b3ad40533693976aee78d42436b8adef974a9db32ce321421880fd5597e9b" },
                { "uk", "e31a920a0996b2b8bddce99c4c2cf0368c3fb4338c506b7e44511d935f699a1541cd743c60c43d4396edb40b77736701ccf5ae78095033729ad5e33839350613" },
                { "ur", "daddfa30fbe5bd80a39aab0774561ed852320011ab7ebe024223ed2b2e5b904e426df6fa0dd8a2c299516e3593a33266c13e01362fd6df898a5d3add891711a5" },
                { "uz", "33e53a955c754fa890101203e7e506bd22007acc497cb0f49aa1227cabfdcc05c2abda0a2082d3e0746e781cd189f7ea96b649a1691609595d0306ce1253b373" },
                { "vi", "7e92427a4e832237cc0ab6c2e54d76de097cee6c2704901a42c1acbbcc50c7596d7d893b38d2bf61d8e6e553b692bfbc48c110a69a3c119808340e7b5a051da5" },
                { "xh", "bba55a678b91a3f1faec3d3b9db1b8ddf706f8e792218c07f20517f24802fd3649a1b2e171d0e1dc6c9bc630c14fc037e23a91c9d9a9557b93a6b6d2449694fe" },
                { "zh-CN", "797611af08c6110d8786cff58f7878efb1d14ec22c95097dd76d5c82451603ac9d2457630a5181b3029b27f55152139d20fe54d2e54760c0cb50b3412efa70b8" },
                { "zh-TW", "6151d79bf00b4009a0b90be49c07c55b68795cef612e53cf874e8ec3e3ce390f25891e7758fa4cfbc3590a8db5f16a195295f009a3ec6a1ba8e4a1f45ea2466d" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "138.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
