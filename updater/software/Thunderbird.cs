/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.3.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "cad8e8d030d338a735d684fc60bee9807a9c8a97f5d82b530a9b11236119e1294685dd31e896e5efbb26ba51e0513b28a6f102e543a731fc719bcbcfdd65d37d" },
                { "ar", "5fccd1309ac4bf6fdc58d6ebd7dd54037dbb0a5f40d6cd1e2fd2cd1fd4db6bf35db10102c613fd7daa3976a3c3541f3acbccda04bdb2f45ceb85b23864ea2601" },
                { "ast", "c3ac59646d0e8406f6d5b47c4f8ed051f9f181a74bc5020471f141c55b8b3be8e3a5832a0993e952f7d6b6f74e25d01656373e029f62de92a771506cd2515b09" },
                { "be", "ea20619b628a5b3798dddd456b812cd507d154579e8ee7fb6233056da1de797cfb514adadd83444ae1cc6428831ae3c20002c2eb3e4b279ef29f8de9240bb294" },
                { "bg", "3f034fec7bf09a89f3eeeddbdbfc7b8bd12a642de1ed54a235179188e754f0d685ae66fc98f073ef406e6ba95392cfc2da0001441e38e2d73d03d2682a9f67b7" },
                { "br", "dc3463b9ae96c90a1b55b86fd96454c441ceceebd9c8478c4b7bd932dd9f9aeab82c8145be04b024b6963a795a0046d845a8292cb87336dfafd14fc2ece2e61d" },
                { "ca", "3e004cafc1734c50437f84e0ca7475638def4cc7d2c3e1e5600996406044925c5b3a58ffb3525ae049d728ce88dd7169c6a595f64645c79a39a85584ca9210e0" },
                { "cak", "bacb7fd7d6049b824081f9f1c6e5c2b0db56998e601acaeed12fbcefc4aa20b79b94a2ad459079d39fc347430a1d8a272c794d31bd3409382f4d5a0a46bd9586" },
                { "cs", "4b7eb8b1393536665f264f66a5ca25aa821a3fab73e3d987257c0b6a546a156cce2f2d6d8e6397e797a0c9be10ee76fe751ef465b54bc6cdc24836702dbcb9e1" },
                { "cy", "daef4537d02bb5b34f0b115c0119999cbbf394bcbce027dc26b5f7634732fd9cae3340ef6caba08299b1c4e8152d894cd49de8d0b2fd99f42ab08bd324333eee" },
                { "da", "31f97d625777fca514d8251cf4f6b3bd1f4c2457ad8e23ef610ad593f13714309d9817ebcb524aff2bf8c6fc907497d0347625c8b78a57a37888ef8d2141ab5d" },
                { "de", "c62f77f1c0bfd889bf3a902128d9e75a5fe53ae1f753e91973b8c4f896235b16500ff7363c6c1bce5ef7a83abdff7354103e0ce6b0fa67f6897f2b0d0def7610" },
                { "dsb", "a1396f05fb504069eea8917c1f98ec29b26e56170e1780fef151cff1b67d38f67742319e7e47d49d8cf9beab9442ff8418d8dcd7c66783e424ac0844b552f03e" },
                { "el", "f790cdc378683218ee076da1c5efa7dcfeb3ee8bc532d4ab8d41bf53ea2f3bccf7ce6f4ce03ee5a38db609ad8bf9d88853c5fd6821de71eeb2bc30c6a2eff929" },
                { "en-CA", "4ea49fbdd3d600749c3e721512c44db23b426e6a9e682bd60d3578c4f0ea8342c27bade0d521a588ffc5c9a983dfffae6cc428681356f638a40c4ae0df710559" },
                { "en-GB", "9057b5d1a8336e52e101294d4ecf4f7109e8871bfb4f245e13715bc12791091acc4a86a842189c7d393037528daa343e6981a0da6a26748e5544d3e703b451d1" },
                { "en-US", "162275e4efe53e15d65a21c37d54c1472f30f81783485a3523631a89ac58e8afdc711c26fd6f58a7860e2cc37e92f906b0c0959fea0871d40bbe56ed26627e92" },
                { "es-AR", "bc18b92da325ea62cc7a2dcc0f39a10d542817d1c27c466505e4ed4d8f9525d32014e2057d2a4f72884479c9ad8bc2f9acb4f86cca84289a4dc8516ca04ccdd6" },
                { "es-ES", "70c18577d414e1eb5ddf4dfff7607aa6e1388b161ccee0b1f5ac49de22c5faa3ddd62534d1426af485536bc4a15d497d53a59670c7ee2767ac2546fb6a870fd7" },
                { "es-MX", "6b751a4e90087dd2193011712cd8bd4b3f319896b7dddd256538382e99e95dd6d2b5e16df37b6a3322b7ce60475e0380663270e667eafaf55d44a01f3105fa6b" },
                { "et", "94e57cb24720d0b85638b5f988e94f455d13b0e32f6123784616507f905da402bdf694166df059109293357ef4f40e002c52ad08e71345ec1f0a31b91c294c08" },
                { "eu", "ad36af2776b699b72a2e567b708d0189ab37852365cd6a57d07752774409e4fd2dea9a1fee343da355d714f1fbbf25409f6523b39ee5e88873cff6dcda438c8c" },
                { "fi", "1787f0a9dad28ea66594ae3dc463b6b50368dd717e57b7854afff9094f577bf295b1cf50e1ace4ca8a8b777ed9fc2fdb2a338bd1a95666b46666e2cd37e19e6b" },
                { "fr", "a27af55eb5f1dddd02e64b14882367f67073528f095b0df39a74b4d9d9dc5786232a09596d2ec9e9a1a5775ce07934500f3886008b28963b8c80622742b8f187" },
                { "fy-NL", "5bd8565aa859bc752674cee5c8b3e57aa4b1f1306ca1d59025d95b1b6075d4a5faa99d20d5d04d2658e087efc68fd4ef646d67d43dadfb5d93e158c375d3d195" },
                { "ga-IE", "a4776d377c8d398a5851990442d67d50cc89b880f21eedd8b349453e83852c036bd480e53337daae417e23f600633916512f734a2bb6979bf3c0b9c137e29bc2" },
                { "gd", "52beea2b461973bc563fd664a94ecbd485e914a92fbfd7140010d6d45d6c138432a43fb3c637957ce33d7806c9b5e801c8b9de99b91ec1286f677470210a8314" },
                { "gl", "3673d20faaa0cb57e9071678a24e7834748d44787fb82b63e135d3b482b6fb0969df171047fe3eb9f0c342c3e26c639bccbb21fc4b6bd0fedfa3cbdb6ba82893" },
                { "he", "dc906576177ea7bc0c132a2dddd23af13c2244f141acea6ea635a5fff14d2478d59ca37e1c000ff80d562d1da6b0e0b5daa60bc5e255461ac44bac37615156de" },
                { "hr", "8f3483fc224e53be44b0b9d48b0ecd19deaa44b8d8e6c42e5a1233cd3ff2652ec9b6698451b109ab1d38a9507c129e5099261f6a6fed1be87285434654d63573" },
                { "hsb", "dcaa43d57bcab6d1b9271f17df7699fc7fa12d1c7c3731a8a7a941c6cc3443457cdaa418f162153b3bf432eb8705775fa0f7ef82270ac9d9b36db486642b4479" },
                { "hu", "c4e97c37fd2d54a8d3b9db2355d9c503f6a13b1940549a4c3c2b7d7de6a0a3bb16ee3c561634943bf3d2c5066bca3c80cb8e1a8424f698232aec2cff87cec1da" },
                { "hy-AM", "ef2c68f3460504b646be5db291f062005f55841c0ff18e5a3cd48bd5d951e3395cb90d5db3b799e516d23371263e2096ad0a33d8578773d60db4dc1a516c247e" },
                { "id", "d65f95abf934bbd160f10c1052b355f99a40277b803a755ce1d6c244d32285052737d94ed62a7687981dbf5a91275a319f4521e576e6eedccd94a493b81a201b" },
                { "is", "e5baac7955cc836b493439d19990334ef9d1cefdae5933128abb5906794bfec32bcea9cc9ada462a7ab6eb495c8f79225d7fb9905687911306f51d37d2900250" },
                { "it", "148cbf132a1e397e574242b54bcf8d5305388f5754665fe35b8ae10e388aea16c9d15023ca7157f95b8da07d1cacfb7e2d9c03e58fa4229899fdcfc4c897a7d2" },
                { "ja", "1527dc120d63ca2c756e47161f519e35e1f2f2edf6933f6191e373a394e233df2425fbc42725ca8f16a210eee65570754844278c6904d4922efd4e12b189c1ae" },
                { "ka", "b1bf9493f8157a5795c9a40128c87d75baa30ee7f13fbb79b46bc89a534a00cf9e6dee8eb55da9fe29b93ff75714d1b6cb96b53380ba303fe5892a0dd4979b8c" },
                { "kab", "5ab787b360cc9d81443197e47ab3a9a9fab8d53f11439870f9f87218c195d5e15d71a47b40de024ad6cbc2e853390f2faa51257f45029f891e574218c5db9e65" },
                { "kk", "58887feeab295ed22ab535ddf4c2999c3ad05e1d5294522219236c63c0445a474fe0ec116853e2121ee442bb49b1411abbec21dcfb4c19857c687df88c3dc392" },
                { "ko", "acc7dc6bbe3eb33b5e10b22637355498aa15bd5f7cc77aaebe6fbacf8e4ee3517cfbbbe37094ee7dbaebc9e754d548a218d7ca05b403b2c470317c50afb5ec2f" },
                { "lt", "12ccd999350c3a1475d53b21b0dc2d521b943a5b6f5ed5260cb8be9068869f3feb1f692b94e163050d5a8ca5258cfa0a8cb9d9cbc89dadeee94a176c8abc071c" },
                { "lv", "7bc8d9a51cf5cb9964e776be233661bc8a34637304c5931b542eeeb329b9a1b1a9ebeb49efd63ae50d8135f906c3e122f47a1c78d13923c6ab3f623da3ae90c4" },
                { "ms", "8d7757a564b8cc4b3a178c953009408267ade7a6d0f508f8943862073a310f4d6a8eea3e39dc3ff1daf62905be164d7a81d87204b1b6bbbb9bb65f1c5afae62f" },
                { "nb-NO", "ef82d3469604f8b41de7a7201a5bb6fe5d389a83ae9c8fdc93548a8dd1345349ad44186a023a52d07fb1b29584ea148e13111c883e955400ce3132426a4dce9c" },
                { "nl", "2df6230c18c6f81c5d5fd55ea6a8d5453bbf7da7789ff3db13c6f8ac91509d767f1a26cbe9efc747f088c91272d1603a5cbbae3c8a1f3b6edf2ea6f69b0d2999" },
                { "nn-NO", "0689f48b5822154539a0412e367363e7a3020172d4af28d666b5eec22ef08bd6f275ab8444f519dc007238aeae9267786ca0f04c5e3b9f0a3a68bdfcc95b87c2" },
                { "pa-IN", "9bebcd759000231f8eedbcbba6799eb859d453f85c431fc1347efcaec760a29a86dd0450db98b5925313bf200923411585245b5a6718beee3f9e8f313a26cc69" },
                { "pl", "46666c06cfc488ed6722183481ba3815e63fd27335472a8469abf07ec0721e721ec2192e464726dd42537da2b87ce3c3275989c9944cabf978edc7d606ceb2e6" },
                { "pt-BR", "b43f7dd9d4b8d1d9ff0a3e106f6c69c44685eeea07854bd51f160635a9dde4dab2ef17374bbd47f495661cdff0a461fc5ae5106fe984047d8452328bd578a1e8" },
                { "pt-PT", "8d3e03cc3f006ca0a9ad901c3fd60065d23612ecb9fadaa09e7a3f5168a225dcac8089da0402e49a8939f92d8379475f51ad59d27bcf978f4f46a80a5816d2c0" },
                { "rm", "bc0f6c776c2cc0769a9b4fb76a76d9b22494bb4946f597d6266571b16482f8048674969c2315005735f19ae92617be187197886aff35f0b55cdfb1f0fc3bfff1" },
                { "ro", "d7873b5c263ea66ab9d7a24134af9e22b4fd75fc1973f0b40ba5eac5874a02b413951d94b5d11d753c4bbac9f5ed25f1d1a779621e449fd3460870ae5b82d750" },
                { "ru", "30fa214f8073f9aa9cdf5d5cc0678388c929434e27fddc6f2baf115819016d51cb55ff3d6469677aba42550ed8e880af2512b0e70457ef2df1d0258e643a8e54" },
                { "sk", "b5de4e3d9adff621e8d4aa7d0cc979126e7b839e9cc5e26dc06d5d814e2deea23cfff82a909e0a09a410c69fb57de463c596913878fd1197cf5c7b267d3d5a6b" },
                { "sl", "434dfe6caa90c9871c2c48a26f1a087f781b4b4640b8e8fc634a2348ebe3707b9672e89a28dd0944e1021d55a658fed36582d8cd6369852427e6378cb51f3764" },
                { "sq", "7f8d288a047af2f3986aa5e93a04aa27720051d983e4395e1f4f009e58c0f07b6b695bcb9609f1216d6b432d5449e4ccf5cf231e6723fe1c00cfa4dbc4d14d85" },
                { "sr", "1c970306c5ada2aef18d28a6c8bceb2a93ff4f1b46e4a03d90b08d3e9e4e6f934d28a112d46eed4e2a7a7e86ede37307a0599089825e8446f4b117ea21ce2b6e" },
                { "sv-SE", "e2a5a248278346cbf36eaf77085b7a248960c1e042fe90ef8d05d2135a0b3cf26b4aa38fa7dee6ea815cc8487d379660c6284d80427592c1aec9a213a6520ac3" },
                { "th", "e8a71755d4e0d21c4ee18103d9d3787b3ad3ad54cba8471f059109c2d606ed033c474a7601acaa593707579c8cec37876e9a9a2dd3666e19f45b2764b2891f08" },
                { "tr", "3c7042d487d0191f65eea31c16cb7deb23aac793a0f644510c68ad292330710c32a97c68780824b86e7ae804e4610811a9369071977fa9d7ee43ede841199951" },
                { "uk", "1a43f08bde7e2548776aa034e4af53539432d9e01b550888007477b5926a11c9a3e3ee9678872e76c56a8cc604eed1834b079ce53607423daf9cf07dddc10a0d" },
                { "uz", "483ec89485c0fa6cc6e764b83d72de52bc14dc5def7bd975ceb58d4ea848d64b8c34d288357c72da49204c9086a609349611fa80725c665632521145058d716f" },
                { "vi", "be63a09ac723a5ff1ee947ebd0b411aa3205853819e48e862be98c72ba5b797438e975bd36b6319073aa7a14cf882517e91312c1bf39cb5d53148ca4a4a455ed" },
                { "zh-CN", "37018a48cb731b419b27e2c483a382a893031c20fba49baf894595cf9b12a35a16aa092f59f9b476b07aea986c4ed9646df11db51e7fc3e0dbf060b730e609f8" },
                { "zh-TW", "ba0760de6fc26687727a15d8e656bda97a7eee0a8563293effc8b47d2b006379b1ecaa96ec15b6ace03f7d363f5918e27e8d688b39a8b7e7b948a7f4a5c00bdd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.3.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ef809b9223fa9c0192c26bcd954b00974c54e723b2ffa5c67f1a2ebee042d5fdad5e3e195b4f2f6e4d1c42c32dca19524f10452e0cab73d2a94feb4d7705d19c" },
                { "ar", "f58c74ea7644f2d5d3a2e1d10a8fb22ff79f1c9cbaaac134eca13d9c1bc72d46bab6687d142a1b42e560a4247932240f0fa32f943ee5d49999547cf152e88a74" },
                { "ast", "3b310958aca96618da58afc2ef4c7a8cb9297b01ceeff95e361eb7943e667ed1ed3320ac9d9afbb85896e84a94a2c40157df0b4ab18552a3abda87bf2a1a4402" },
                { "be", "4eec31c9fea7839cf230d86e641ffaa67d704286cdc4f23f60049b542cdb3ac739678fade35635d5f4495ef85a9e8526dd4f178294d922ae185c7e58f4100a95" },
                { "bg", "b2a463e90de6001fa22a8715f980b06ae0e4bab917a5795f7b4046cec7fa11fbad7de1c70662f419827e12ec7fefba11de2d369fcd454a6f32380e548e4596e1" },
                { "br", "87421563458d62aea399a82d6a5452ae7ff6cfc810b8bb69459f71988f96cb4bf360918fbf6f2bbcc78e60991647c1846bdbb744b28f54c60d836ff4ebb8b78d" },
                { "ca", "af8a9f5ca4c2ceb022cd4d9573b9f949b66a84c22115ab3aab3878731e2274e1578d957907a8a1e813f52bd9978ca32c4848cee6f5faa24503e66577fe2cc495" },
                { "cak", "180dfbb4b5ecce2434817ac429685a19240d48ba06d43a65527f28af8a3cd13c7757bdf7543039ff786e5ea4f10c46bd506d06b9efc59a8dbd3ccac26ba40221" },
                { "cs", "1b10d8bdbfa97a2e1a0eb559d6abcc3597aea15fbba7ed42845a2ea0141a21ba654cdd9fee955c3fee025424f0c43d05091277b25c390baba22629a8794d71ed" },
                { "cy", "b6df9fe2e648707181debfa1625951ce0d039e54fc1ad4375c6b2ea5e882327664e8319b4230f147dc25fbc895d988c618edb136527aabe8e015a35b4c6f12c4" },
                { "da", "5ed73d1e062c0ba697cda5b5d0f68ef969494d68b96f51ff833f9eb8c834554c912c505aa39cd42f1411ee904c09dc4df1e8d6de26fb51a78875a2b3e3f4b6c5" },
                { "de", "dbf7a39266122310d7daf6d6738d775d25c2421b9f493df5c7312133f4d5813ccfc0caa6ae8984e339c76a3b39f824239206e01f52e4e950320a4bc6288904dc" },
                { "dsb", "aeb0b22be481d877291b69219f01b65542b21e420db0c9b6231f3a01e1d28278c691c07da2d78b1b5455d1b8e3d0595425d8e52b80b6a38245d4f3caba24415e" },
                { "el", "625c7e7ff3c7152c7749b49eeed9e6c310b45dfb6c93765cde8616d1b588f630b8def8fe12abaec53122ded944298f71c8fe8cfbf0b75a8f9d9844b74c13ee99" },
                { "en-CA", "d8dc055010d41eb3a809d191e5c7e8793c9b75187d6d1905116659d2c7b7e0905781d4bf5020db84dbe56bbf0df381d4292f9a3e79637f97337f3463e604b0b3" },
                { "en-GB", "5bad18081644076bf665fc09be7f59ad5efe6349ac0a38f430d1e9e1f83e6bcb08284dae8564959cc75e2a5c7b4380ae1f003e41899fb7d5ecc5a249edf5c2f4" },
                { "en-US", "866a9105286e4f8d7f6a64e20b63f9282d82a24c3bf97e462bb2ceaec0cb3abc2eba256c230ec33d3d4f54217ad091a474382674f3ac68fde2c34a0b79cc9cb6" },
                { "es-AR", "63711874c33f84d9a245c3589997e2b3c34cb42a4cfca080b30f48d16df5ee77b95c28b3836f4b1a4c23d990131e69b0a14889a7082fcbb64e6b1f9a257575fb" },
                { "es-ES", "8d56eecd502d97590f028f01b5319505f63fbe5841c6655751fdb8e5a24280afd0e417e76efa90b1d06ab835eac4bee7aebcf7905fad8afe319d5967c8533085" },
                { "es-MX", "ab52b246a92af98850a05d92a4abc2e48f5e699b700fcb486a7ff47f435f2245d2ba7e2872070213a27c72dddd2c213579db7276d5a24e98b148cf062390a691" },
                { "et", "55bebb08d5041e8dfaaf7a4235334bb9d43b7dca5440194263b4177233e94fdf2b726918fc314151174031830d7b17689fbc73a17254e7fe2225e9e014766b19" },
                { "eu", "0efa03e0d4207d29fc567a72916863a68a12d71fed383991d0f1f840df45671757689e27c9b451e02137234ed80518780bdfdec7900b7054f7a89e5c3f6e3312" },
                { "fi", "39b8af986f7bbd6cef4196a59bc6dfa33de2ec6c80663525393939ca519b3544a0fb12a7229ca592bcbca1b4cbb7198ccaa5f7373f7b9093b89215fe35d94b77" },
                { "fr", "41d08625b4241399c09748ba4aa916039790a4f4a037d3ce1672f8d8d0912cfd6d7a9d8ca27fcbf413600b3a6c60a5a5fc950ae186cea30bfc6d928b54fafebf" },
                { "fy-NL", "b41cd317b615967a167879af98bf562d54381e573a6f3fac687d2f027fe99f00d070f1df5c12b594df5e80daae3a006f282a7d666b5126a5480658b54a586bbb" },
                { "ga-IE", "de793e8e0673a916dd91ab6bd89dfa79be70616f8fe6274c61bb2fce40367e5a09d9ab721d95820d3c2fb128fa98d9c38aa21af3ca4567ec4172a42f6a24d575" },
                { "gd", "3ca1124f44d02115d1d6f3d661863971948add5ea8ca8e96c5fd1f604485dde3b70d8f166edeee63f4305fee0536faa032de3727710970b389104986cccc96f8" },
                { "gl", "5f871403f894e63d62cd780a9bd25b842a1b1ede5633d8be39fe8c0f40c4a51547eea6b9cc5e2ff8ee48f8d89c3a433c3999620bca1588ff3da741a9fe07e11c" },
                { "he", "ea96cbdcac96b44406e33aa933c1567b0b46a1164879d9bae5268568d55677c00a0a600a44e6ea6de0bb3ece9e8f88c495e1fc3550808acec4991f7666e18826" },
                { "hr", "1fd668d21cae5be3b12cd21033c3456302e8aa1832c9ae0b229037ec6b69180930a5c0cdbc15ddf79b9d36e90cdf6cb064b13daa21fe113c7f0a6c6ee7ddde23" },
                { "hsb", "7d4b807ed31c5141a63043cc72d5828bab3cf81ce1dd75b593b714d2892ee62f51c3a232c879bc68a8b07a5d2ef825c94ed534b339618519db5c694386df9cc4" },
                { "hu", "10f0a191928716abc329eb3a714befd258dc411aeacc27f710f2a30c58dd4135b7416458216c1b867fd5f8d782788f233dc9136e42a3bdb18c17a394c1399868" },
                { "hy-AM", "9f30bbdc5b1a9094ca08062276804911c78bda5c8b40525331bd33ce9258da02d1414bf61c093bb4ab42c04ef09e44f3169f79f8363cb967575d4c75b8727aae" },
                { "id", "ad8e184cefb6ae4c0f9f2eeb9c065dda915293c74972ce3e76b773e9f90452f38e6dd114f79756450eae0b361fdb8061480eea53006a55c0e65d155b6500828d" },
                { "is", "3844da3cab2bff74a61c618190ef02789c7a5b403d0413cd13f58c4e2e8edcb6ab944d46091c593ae44215106ba5e53b4c311c89025a1835e01552ff9d53ab32" },
                { "it", "34e92a3ed1c2cbadd3f1105ee8b8b4adb4c6857de288b8beea9775517aff169167c25ace1c1f936c9c13e7b6d6b1f58320a3dfb23cde3f14fd4e391ff5fe18db" },
                { "ja", "6c874db03194c1e7c763775381e572a4ffbfeeb0942088e1116c1a1258be041dd4cb8a0b061abc3541b6472d422418d0afec867b9d585db2f2fd940b3da01cdc" },
                { "ka", "e0167a0109b4edd6c7520e17dcf1ceb0f5549d5c161bf05dc9d27b407bba0a84d9a41c2210ce11a35fdcabdad269612387210718c763c1e10e99357fd760e2e4" },
                { "kab", "a16040111f821a10b422c8092a339eb41e69dc675511c7dbdc8e0dad4b61a7def732769c1ff4c6fdcaa8414772a2f8aa8c37f4c71e1cd7240b8fe1b6a74e62cc" },
                { "kk", "df10f4b86c8f68f206e1a6b4fcf40463f044bde46c96286ccb481e690961112a9f02c1affa3db2edd34794d8dd5fb4560ebfd112d67141a0ce8e6d6c637c1f77" },
                { "ko", "bf06583188a08b72d8d2f800909af4689b1168626681ba7c1802546db6bed349506e8257d41cef7292be9565256b3c8da927a7c21198f2803c90129fee050b0e" },
                { "lt", "bac5263bdfc7ec3a5077494d3cb1b9859e50d8bf52e5c2f85955b8e3b891c6c7a524e8231fdd2164b0d431dcfd4284c899615c0ccb4b694d685634812b96df47" },
                { "lv", "2333464fd1d30e2aa70ee82e142cfaa9fcafad08c5be20e75e3bda622218315ff3f391af62686adfd20062bf4d4e9a63d505879bb9bb58374be47cd9c9d35658" },
                { "ms", "105cbabfc847da199a8dbf428aa3abd339e4bb5608bd58dcda636087f9da04768c662dd93e9730c509b3081259af50904045521f25c71521ce1d82718741f4f8" },
                { "nb-NO", "4e1341cbf5e9b2d8b0ef46096ebbd5fd6b9fb2cf694a4ce5e7dad3082a05e5ce117adabbcf6a4f2333fc93d24d4fa0702538c91bfe9979234f0fb566d6c01c43" },
                { "nl", "7657d5c3caa2373b0c642d2b62966b10cecab89f75ca16434b7341b74c0efbb2d4e7990100a7d3cc18c784d01c326c9cfb83b5ec895341c38153686594ff59d1" },
                { "nn-NO", "71ba7d3e72af6989da61443d2093a0d1ca5a124b5974fa063e0fa0ed3c95551ff096c99e4f8f9f68dd69707bb9215433eb3bc857a50de76eb22c3f95532ca307" },
                { "pa-IN", "7dac829e96e7dd0873417b23792a304ad53a434f8bbe93fec2514a46de92119669f24053c073dc3b497c67a4f2b4e03cd9b089d511a6668261d07898f85c84f9" },
                { "pl", "ed544ddb750a93814d31f5f2bd0be9b371f325007835dd8ba29f8ec6bdc099c9a75816faa745c2b5401d9e2f2c50097d3c162446f65be075abce1b394075eb4d" },
                { "pt-BR", "037156722620383dec476c6e54628d0e0caeae99c04d210ec893ea2b69f2e1525bf646fc24d7e5a6568f1688390b35793e881a41a1615156fd82265fb2791a14" },
                { "pt-PT", "2d2667b5edaf546776960e0ece4c2c960cc40932b666ddad4c0b7bbbe440320554b6d1fe523af32285617e49a996ab64c6725c305da9217c8cbe6cdd5ab4c452" },
                { "rm", "a82e9f4cb358fa6ab5787919738e6b3c2f2d72c77e39d268a2f9a11fa8f7446f9f283b6c97525fbf82d82be7670811546cf0ee13633734709ffad095641b02a3" },
                { "ro", "3e47622630fc05f337025e4fa547d106310dbc7eca5ff491af8ecf4e58da900706f2faba2c66d5a46a1c7c42a4a36bba31262c87919f5d95c2c79b321efe859f" },
                { "ru", "88067da21c2bc3dc3530cec25a97e3f1b373390a24fdcd3a58f65dd61de1892a64b5489fc8ba6489e5c8cf493211ad5a78f78f11ceaf72042002d1c1c0b8043f" },
                { "sk", "851696651c1894a219cf46c3619a0353ddab78944a26c4460b513d81a4bc50498a88d22ebc8f07a538c4b1484142342575f98c15e5d32efa3fc101a35d40877b" },
                { "sl", "c909c79be56e77268ddcc40e48d0464e8b84da08d256c3db18fd3910407b8f69f6375c6a54af5a108de848c0e7677e6f140cda323abb9c1fe35bf6ea014f5c88" },
                { "sq", "ebda07af44e2504e3d93e88261da1d5dc5a0cb512a4ca66ae826748ac773e8b51c38516727e84ee5b1b4843f2ab1ba4eb1ad0bca65e951381ee0d0fc44b3f6d6" },
                { "sr", "7197b33e1bee715bc496303b4d0d54e98f6a7961d94ffc12b8317678595d28e2935f8c7a5d9b97e27439274837941d32278c840bb41eb8fd37911bbe9fe164f7" },
                { "sv-SE", "db2371d94ed7a1ca4b452f10a38181facd6c92c9148c4f50fdfd8274954f09d918cf5560b509deb6033c9fb015533e1c901cfc816bef97f9d7323e8f6b3fb5c4" },
                { "th", "361bdc5ac7566cd0ffce8ec0ad8bf8e37f6859cda017c7906ceb009db399b131388375402d1abca03f0ab8da7d211e649314c00c90664ecea5bb2b0959bcb807" },
                { "tr", "1453503bae7b9e1e49049f397d017ed0c8f4089820ea8dfcbe8074cc0b66b1c071405a6d15265cf04ad4cfe879998d159d1caea71fc84202799d764caf321f69" },
                { "uk", "9eb99785e1a5d3eedbb69ed1626d4fc0cf1bb2d8669a97146b9d3c073c59c61615a9a3a5ecea88ed4bb23f0f8352d45a639747a4ae1d993bc7cf1f18fd1e0777" },
                { "uz", "15737f2e5a2d2379398374ed8ec583b9f91bc43b351e8e206ebc118cb89a23bc0912f8400ac4abbbcebd3afefe707d0de2afd9806e5340b63063313b9f010312" },
                { "vi", "55c0d33e18fc3bac3669a5dfe0cadf5a385fcf7e2fc6fd4ecec95c9271a4464381e315bc2360e37f4769534042915325ba1aedb2390c7f3629bf1ea3103e188f" },
                { "zh-CN", "a4391efdf637da5fabdab5329726c1e2f7dfc18964f2757d50c277abcebfb7ef13d108a53f07088bee373174d5add872268cd85131c59eb90d255c12fa3f620f" },
                { "zh-TW", "3684b831aba2202d908b442b6b413603bef7a2aaa2a4315eaec4d2afc6c093dcab50588768cce2ef4ee5e1de961ec20e0a0f3771ebfcb80a7b468d8c2eb3346f" }
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
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "115.3.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
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
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
