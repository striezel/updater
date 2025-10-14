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
            // https://ftp.mozilla.org/pub/firefox/releases/144.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ce61b0067be2101b1ef4396134b6cbe25364c07acc577c7a34e493846ddf6503dfdaa714f940b97d38c195960a9450d840d50d2fbe56ace724792fa41ae86276" },
                { "af", "2d2042abc15456e0d2a4d5df2c6cd861d53e0e67b685229ebdfcd5c4078ebc797fac8192da330364924db788153365375c720aa6dd8aa96ebecdcff068d4f12c" },
                { "an", "f7d2948b56c40a161e789f746a4e9ed2f1d908a51e1b008ebdb2923e4223162b6ea1015958510f54aa273621b5e7d5369fbbef442e1af303e51286d433c55605" },
                { "ar", "3bb7baeeccc46173a5eb7c8dd6d56d7dd49e3bc964a6c43a8af5dc99ba0eba6067d0d5ad89e778e77baeca8207f2ea796c7f80fc7e0acb8e94b2637b310156f0" },
                { "ast", "e315959544a1cb014664ebde95209ae989f9c3de7b3dc008ad6ca58a6f5d51343e4ffefc025c135a63fd1e90f55410683e92e1a6b1facdff0c5b937539daf953" },
                { "az", "b195027d5fecbf809e770d88c7dad5dbb4b8daa00623d683e9d49215e665fcd73f8253df346361c6d25f6bd139f001559d7e0198caf840a447c448e01f0f11ec" },
                { "be", "bf9105184280ecbfcef6a62eae1227f8ef1ca68717f9402ea5c609e77d4d41c35e1ae8e38461babbe39f75dba4f029f5914f7b4c7af64557941370b9bc56430a" },
                { "bg", "d3d59c701a6130bd0e3874be0780eec2c3501031f7b7a92cbf1ef3623278f0a7d048dd058c1e7c5ca4aef28dcca79995d285e1c33b9f0ab475d9c75fd521a520" },
                { "bn", "046786d2707f0580d737e345ad20e14b79a2c0f11dc405b919be31865560071c8ac40fb836c685c036830ee814c9afdfcd6ce1b55a9af1a00c6ed7f0f4b0c404" },
                { "br", "1063d0b932c5bc03ab19fb1557c370774515ad4d7fde963da7e26545fba7742d25a2936cee79e008fffeeb28e2e6a77090610ef6a9d18996b845989366655a2a" },
                { "bs", "b642fc0dde9f45334592941367711f0f6d34b673fe6abccfd3225da2db78fd300ac169d63c9ef7bc705901b88fb02c783e84189e31958b1afd0a26df7e2614ff" },
                { "ca", "c522e739c9df8efec507299a28dec87d9478f4f1b4ebfdd9998b38d4b8c0a3ec07e1b612d4a5b6baf261dba911ed6992fb8ad93614e759c090a009c2e3f7aa49" },
                { "cak", "e4d6f164bffb04bafaa693aa54d8b2e6fd2edb2ae18f4598be4f48dc43f06f1a62385acabcdc8cbe82e0d986cacc5a01443e8f426273308a72327fd33b1eac2f" },
                { "cs", "57ba2c3725db016d45194805fb0366aee2e0316193ba5f5a8d4cf04a01a8261c48ad0f6aa3aaa0d05688f42585bc8f3658d38d2612e8b0d735f2d3f5fbdc3630" },
                { "cy", "4b6d0b18a57fa8403fbe8abd3ecb066e69c272b3fb14ebff2f05086fea3b6d3ffa0f0e1049ffe9028aed28cd37526772ce26f5b583e5769cfebc99865033f433" },
                { "da", "2dfeaebdc8115e6c044718b8c96b3366d951c44f93a7cb63e3a8772281525a3049cb26514150f9f7bfa24cda42e1ffb4cba84984c3f27438045146cd58e2cac0" },
                { "de", "85eac3038aa87bd9b0c228be04b0b3e4894e064eb0660057619b1f22b14d310bb8d6b445ac8f7f10e79209e055224e0b980295d1f90fce1ffd2973421585df80" },
                { "dsb", "e1fba50dcccfdaea1c819d925df3b40974a5cd6d152c7774c16de8503416edf40635820d4baac402ee0af53025321a3bcefec933acc597e57a8dc4c78daf604c" },
                { "el", "c4c56826690cd14c5dc4305c8b26ab5184deb150f8865e889369dc67608932a53eb3248b27e3a7f30155ede6534658f45bb79953843478aa78caf29e87ea699d" },
                { "en-CA", "7e78912a587ba96d49c3a62ab59032435b0cb9f1860f739f919b28cf817024abbb453a7533e099faab8bb3c3b787edd8e06afb54ed1ddee9714aa6801aaf71f8" },
                { "en-GB", "2ef5d1113ed79e0741b87ce0310575d3dd7ec643586511ffae84bded64b63fa7e3c75f6dbca5400e997f3a096c9073788ce4c8cff829fd09d862e52ceb167351" },
                { "en-US", "0ee34e51bf72b82b378c40f591bba2648f415772c36b95f4d112123e3637bcc6cf4f197e0d20550ec453e04e3bfe5fb40c57dc53fa5ce92a1b37b190c2050567" },
                { "eo", "140ee33f03c601bd2cd59308795a1c9d920ae7ac76699a17078078739de38c602ff291aeadc497eb7efbff464dba66daff53ae8d5b44f463ae54734ce3419434" },
                { "es-AR", "a66b37eb9c4b813f706fa2b0207c9d2d2258b094246d5dda04e8b63ae6d30430268ebd9e1b1caedf5093a5bbaff1c792272268a0f855c01fa22664c9055b5a89" },
                { "es-CL", "54664c173a3bd59a3211458e831ea1a8ff338f7a70f5920ab029ff012589d9df5d91408f299eda4e35e55635b0ac5f7326eebb745c89c0242404fcbe862e21b7" },
                { "es-ES", "8704cd3c7f0c93afb69f3efd66c272892a719730d5d39b76c404c67148d8d7974c315268b3a447abbd0f1605f6a92a3e82d0db7cb6b1d39cd9e4740e68c556cc" },
                { "es-MX", "82a4b3fffd89e7bdccdce5a4e697e40757c04d79503714f814b2c69cf2d55579ac9ec4b2d2c024b027dc162e6f2f0a67df1c0d16a2038138f5847c8f39fc2779" },
                { "et", "26a345ffdb62b2b92bf0ba5ab638717e45861cb2aeb5e497bfc202f4ac6f5350ad53e234e53d4390a67cc98732932bed1cc4f8295d43cea0a83700975238e55d" },
                { "eu", "02079b96f5aecbdf3f85f21a5fb2fab44faf8819d959974aa0f31c017f01402824407456e13bc5c77b0b847a39179146da1ae07c0ff19ccca1984df94976d9cb" },
                { "fa", "ec2fc75ad0131bd985d45cfbb522853e63e2c65aabad6e347a6c44a5de41dcd1afa914c1135a6c5d8c0a42b4afe626e9090269a671fe634bc2827a58c367f6f7" },
                { "ff", "1f361f52a59a66c5d4e2692a65d30eecb7dca50d0c5c346b7f421a56708a977df79ee616e40034f68c6ae537728daa5807abc6d2d6dbf2ecbdf1685531be1bcf" },
                { "fi", "b6548961fcba624ae0c780defa21152dd8ceb241de63a82a9b648f7eade3f143021485c74b8b96c5f5cecd3ecf28faec183dc3e30a96c2b0fc5539cea6e12c90" },
                { "fr", "af02af9b5f353622cb0b189e6ddd2c29540d2d03734d8eed1667839f52bc3b57d5c41559ff8a2b7f8e8a72785fda1788d8cebacdbc33437005862d01461d7307" },
                { "fur", "eca2b5d07575196c197ea4e431372c1804ab0efbe737f2ff1b19c5aeaaa26f0364484a02b69f33628a9efb39fa8337f9448b5ae1723b00bc5251c3aed72206cc" },
                { "fy-NL", "c9b3676327c12ae7ae92eae3edcbffdab52f366bb22bf085e4464cc21daf9a62c48b66c4904e6c4272532a0b735a6575cade86b621ec48aa044c469f524cfcb8" },
                { "ga-IE", "97b07367943ca51cffdd28aded19c2dc916cf8f1f89c4c4053434e6a5aa49ba4de5ae16a9ea072d257fd5da8ab7481e030798e8e12b113d5fa0f9d3866c41fd6" },
                { "gd", "5f2a66008b5c2590cc874bca1c16f83006c9178f7893d80266debf8929a6f39a21ffd0be935e3a6d744815ad68a94e44747fada40ae84acb992dbddeb9f7908f" },
                { "gl", "57f2366bc46fd8a577a1f58942fef27cb289adb20fdfee9f19ce7b3bde3d5d5a45014b66eed0fa3b0a4081d2863eb8aba0c888e1a478dbe6f92f3d864648d47e" },
                { "gn", "a0a7fc1c4a58edabff0391a9bfcb3362c2817db0cc8b653c5b40e8c00a932fc8bced52d6244e8fbf1e594ea3d1d2fac2c2449e42f2850934b502bae14c82733c" },
                { "gu-IN", "f24a8654dfa7fe2586afbf7321c061976a149ff0c7def7fcd693de239f92f475cb295fe63962b5a225d6d9fd41db87ffecd1427be2d83f1ce99603f753094880" },
                { "he", "804418350349df0b2a8e103a0c5f290ce55b3d3d43729172b464a330a946369045bddbf56235e51c4696c8c088cf5eaed49d2150e430e79730a10f1006457da9" },
                { "hi-IN", "a4f76e654df81810dd7870d93665c5a0743a091a014dbd14e2a5cdaefaba5e094f314df04d997e7de3de6fa97f88e0b88e366b97aa5ce8b81b5173b5480f1432" },
                { "hr", "fc5d6a2cc47fdd8477c8e2c835bc64cc867e021f876037c6d72998a3a6b43d6acfa5cf305356f762d773342a25b7a5546a32e65cff883de5f8d757af4e4bb88c" },
                { "hsb", "ebad06f04a8b8dcbd0af417be5507a8630331d48f8408abd1681c968652dc9e4255658031e178b28359199d517a89c798aea6d53d356caf28dc289a0d3f96479" },
                { "hu", "c519b2d3c8b0d6078a65db70c77d976eccfcd4350f5f3d469e5b3b911778998e7d9c244db129ceec1e449434de40a6df296d83edd7b307eb75238a24676950f0" },
                { "hy-AM", "ca6711cf6e63bc269d03d0bdf72ff92f746e92140df3e91776f79396863c8abeee407a9656cd9ee54a43c3510c7336f79b4c59b471470b261ade9a0b9fe5a693" },
                { "ia", "42451da0d92255f15f2081cd390513d5bdc470db7fb894c0eef37d9bcd312d9715f3c2bf1ee1b25f2ab61060ca10fc56ffdcf5e3384ab06606368e9a1b06aa12" },
                { "id", "60cd16820e5f2849599c19e83374eb1f3e279235ed595920bfa21ad58b4f41c81e8fa9c9c2754827d8082be96786d74d7fc14556e11742e33e9510bbd814af75" },
                { "is", "0fcff4ecc54bd0502e598152fe76b3207a37e3674f4f08a9fde1fbaa5a5bb0da2304e2c5a1521ed1ea629e9cf5d6f1196170c323cde5498cc837dc0039da9e5f" },
                { "it", "773afddf32e19397b8e517ee0f020c819f69f464c26fe3c3a8fe42d6204898f19afe3450a6656f4b0a2a297c378595e9d46d8f4ec7fc4324ae59e063743d925c" },
                { "ja", "ca6e5b284b9183dc46612113ce1e52eefb0c4392c217b85115127a7abdf9d5913c4c123469c12ae5a0123c2692b4cebf51a02f44446f6333b8c1d49ef18304e3" },
                { "ka", "f46f5f4f63ec8a3c4929fcf683c72715fd918c714e1ed4f0394c4bb29da44584219a3d5ae318900a93bba4ba44f9f1debb99f67c9b07432aa63f2292da8d7a52" },
                { "kab", "0af97b2570c6c4e6d58234f3a5874aca0e6fb3e710e5d639f86756cbedfef100eac410c9bb75f6e877c70aacc67257b1ef47e5ce373b41eea9c2c0373858d569" },
                { "kk", "28016f83b0ab6d3abc2e30eb5e0be2374f5367a4b29a614ad84d3dac10ef9fb062c9e5efc5db315a6ac60eca55c6551db94f099ffee43631b8743b0a7c02949a" },
                { "km", "887363fde197591e0b4b94567cf854a3685eb55eb03a5953f37b0659cb29cc2bf18965f532f212a00a68e13e6aa61f530b1bdf8a494582b937d6183f19e8db0a" },
                { "kn", "24511c4c57639b57f259dbe17ed9ec2718d08d378d8531851c09d5a648449500bf16f7db081302301349d4ecb894e2400df95902cd1bf7253c5ad5213a5b64dd" },
                { "ko", "6ca7689c44aa00e230479bcc203965da8f2fdaafe7146af76c626f8847f9be0a15a4711742567dee3a2e7ec710c58b4d09ab5fab1ff15d7cdfe95c71f93664c8" },
                { "lij", "6f0a66ff5a5bdd30f2bb84f5b9e7e27997c32a32741eb19431b225f8bbaf550df3734463c032515d44f745ae340d022c28c202884baeb4205c7eb08485b038bd" },
                { "lt", "39e4ae3ddc489ea3d92c7e8cbba179e0de604407f750f6f2fbdb3e22935d5c80d3d4cefd2b77b776e8bbbc0428c976aad41054b9fa14b8292f4c3169186df1cd" },
                { "lv", "b21467e20150dcd79e9f6575db976d745fa605a76bdc7e413b4ef795a6030112a84bf10e2574f146e6d19f407722b96acba0c7d9217da7f4e4d358e3ddf3d854" },
                { "mk", "872d16039504519adaa34f781d1920f69974222516d1aa3f117c7806c8ea8af0aef3b9b97c2fd9166c2451093e03072aefc49e89a5fa6da6ba8f124fba39a1a7" },
                { "mr", "3928ce56c8d98493164572a6d6ed01c84d362e443738681f50f240156b8f482528cd5f6a88849823fefc2161e94935c1bc6b35ff132076c291a74522148e7194" },
                { "ms", "c9dfa9cc375dbdd0dff88033851bfed33e6ef616f269d2a58c381031a1462a63e5ce58791ea4bebfaf95199865aa4afaa608d3acdda8ab0b26507123e62d491b" },
                { "my", "38cfe287c01d9ff42170f9d6db200a128958dc93667f60bf8217d6560edae350087047b3cb4e5d10b670d12967fde986e36fa49bdbcbd35b2c34c67b0550b3d9" },
                { "nb-NO", "5f677311b14e73f8ba4670d5ba170458755912294d7007d8526e3f3ce2a376d99d2483b8ac3c993efb7bff768acafb26d518953757df4db0fdb572589c1b0eef" },
                { "ne-NP", "03966fde9f7c5637036dbb6380cd40e7018346f1a73807827a75d37a446d3ad0544b432993974a9af39d432b81b37f2fca9f8a9b34dc58c633ddd594c6180564" },
                { "nl", "c86b5e5afe5de1d3c35e888d7568bc42da0ff09c6d3c4e45c21d7641690e9e76e0f6bd36dae6e3afc6823b3f5f99efaa58843c5f8569fafd3caa46dde0514944" },
                { "nn-NO", "d027b149a1287720307d9a67e5d5f3f65e094344c606c5cbe4cab8314207f60ecec8bf222a83b0bb1d715de1cb6d5546816a1bd3ec1dcea8df573eb0ce46b384" },
                { "oc", "f72d6bcfe9fe2a9fa92c8e6170e0590642e5decd84dae953a1865032955798b6dd64ae8222586e330634d2531da3ea06c155f275be77389e9f0fa883508454dc" },
                { "pa-IN", "cfd128b7cf73a5a8bda6b1ae1138d7d5af8a04d2c24c028e47de67c313a063a96d880ee0e154ba0509f718bcbeda924b051bff10d8a645092657479778b1a817" },
                { "pl", "9ceb81ece5ac795e59b372c6554013a1f608fa713e1520c8dbdb7459c15644c1004fa6019f3615c00573f27cc29ec4bfb82d1cba10c39c81bd58519cd2488220" },
                { "pt-BR", "65b51ba2a403a59e96b0b24449c37e45dee1570e4f2e5573390146d0fcee7a1900d1f39a0300368eaa65623e9cafe5c3fa23528d5a75aaf04a272fedd583ca14" },
                { "pt-PT", "651a5f4f3d312651c41ae95c11e31d3e1d20a0788db350edc0a5395067fe54802ed083760be6761d48c510ec73d5e6f1390a2e82c381e479a82cf47ac2231761" },
                { "rm", "6175ff7ce4af71b669f382cfa353ed00fac3a7f99dc41c3e1676d4704cd942bfe2889501b1e124c351ead41632c1fe00be2eb33bca1aeff706ec9361039c9d7f" },
                { "ro", "c1c9e8b22327a80e1b836075a6b0c8d5e34784c33da79c629c1262b46e084c396e3819fbac5d9ccfeb32f51d07da5714bcb79616e0ac8b46e0c715f092c6ff9c" },
                { "ru", "30ba93dcbda94ef0b4dd7fefb5f0a349c9a7eb9101df3fbb52e9909df562347984f1a7e5ccf5796fdb4a325af7b747b00bacaf61b5dbb7f6db839de303086218" },
                { "sat", "b24833ecdf1f246f87c00cdf4cd2d702c657c79220ffee40ed3113949fc99dbab1d714431bafcd2c9bc3bf3f6bcc4a0b8f5498469d8937c9b57f62a8b3d651a7" },
                { "sc", "a0216806f14a4e1cd78ec21e21421d9536eba972cfc4c0dea03f244ddad0b64b44c22ab00c338e258fc3b01b4ff7efcef09ac5463cb049ee9bbc15f268ccb961" },
                { "sco", "ea1e318ca186476a152f2571fe66b319481148e77b4ef17bfb99beadb2f382988f03b2858b24a00e569a600cc1f977717c2813c05d6933e84033b29db0ba101c" },
                { "si", "2bda064375688a834f49d3dc2262033ca7a619996190f2f1c094ca76d52f663a2c11bb06b6783c8104808539340fe88a771573ce531a04005ac143354f776858" },
                { "sk", "a0e8ce012ee399dad4cca096954dd029f4dd5a7ce2c33981979177508c250ae409908b4650667cdb10316ac81555daa38a749f1e46cbe509950f605b9c46f7d9" },
                { "skr", "c4d8df7d4256bcea85ad982c874b0d2da2bc4d669e302c8e61cab67d0517a7453bce8cbacf8c8de0b7ae6c38bba39602e6cb9833c3e6614242d5ab9cd23d5805" },
                { "sl", "fd98c9ba75949428b8d5e38efa38e0a6d1d1ca813027a3db7f1cfc77af5dacac52040231daa683dca0dfe61ee07354430b83bf8fc8cdf67a9e357b406936a08b" },
                { "son", "12fdf69ed3893dca3084cb574420b1219e4b82d9c05430af9f1278164ffe8b8cb9ff5e18f0dc48543792d001b9c447c9ca048a94868fc922f85bbbcebfa4baca" },
                { "sq", "bb2e6cfa471c854e98f2ea59d0f8785011b7617ec886d54d4967c4cf420844d120316d2821ad4fbee6c9c8da6308805b7a3eaf21b2e23bcd66cd55be1108eb76" },
                { "sr", "e2a9b8794d1d5ad6c45425d1f4cf281bb1e6b671765437a4eb036388e79404d0e76ae9a7ab18915023cd61b4f0a6280fa5552ed7eaf383a916ca573327e440d7" },
                { "sv-SE", "2ef2876efa935bb65a32b28057a4a3d07a318b319f256f48a2160ec9e474f75c60c598b920ee827d37c63e35fe76b6d326964d16dd8cdb37caa71cacd127b9dd" },
                { "szl", "aa4eed4240c7beb8b32b26d7605a5e7425220c28227f0abf0ce4e2b02494c3434d5aa5b576a27f9d6b180c4bc5710c0993e7cf00a7cee47f2c68b60e6cd0a87e" },
                { "ta", "39dbab7c0450af439c31486b034c4f1ee3e46d02468d09fa1192c48f43b198d098cf5e57744a944dc8f06005f46b493517d422873760b16110ca14c8d0d5b176" },
                { "te", "12333dbcc5d067832a374bb0024e513853b44ce8c30228b4589e99eb5a38932502c284c6a81573e75ef6a40dfa8bd20bb481d1bf2c9d9df20f67d319c949fed7" },
                { "tg", "e92f03dfe7ee4ca3f2b381af55d19c9244253bf65a3136142ece18c2375ab3aca67cee9a71fcc127b98f3693a082074bd7dab4da64850721c51ae8c9de71f7d7" },
                { "th", "db7d4ef3ecb74d8ac77b7407dc7f6d20294f102b9ed69bd30dd5977f72cf8a80e31bda5784975b9f4bc6779e246c710a89137a673e92270a8730dde4287635f4" },
                { "tl", "224d28067ede30ac961de112806d10bdd419a8ccdd218e7ecdc1115baefadeb849939ff5b339a2de86f3a8e724416ba46cd1ec6e6302928bad146885bf03b44a" },
                { "tr", "8f54303e091b647057221bf7f6fd50ecbd37d78e7e6fd3c3993ab7ac994b455651017be6071974786ade19e053c9d2c15d0be3aceec562418ee427c9cb5394cf" },
                { "trs", "20f004882efa097668f51e515f1f9880b4c18a0063df7afe9b6662a77b448e6b35349c33ce54d9abbe6e16c9bf09433fe76b49fc0bdc1419fa29099fb48b026a" },
                { "uk", "ee19f424368926ae40a99398dfd99f8a43e45e321dd6693bbc7a586553adfa7b0698daffc24f31b5a637e6ad92839e56216e7b57a0c2466991f217d647e03088" },
                { "ur", "257d19f72442e77736310dc07a889032a333040659e574f7f839f8d2fb82fb9140c1222144dd30b461b0f71b05e80e1648977006bce0b54e361416b2dc01ac62" },
                { "uz", "b8b202f9c77633caefa9a6562de07bfb2123b0aa649234627348d5967eb2e6a8c122f98e9a9c0c58fbc9a1978197742251379296d1ae67d2f5fcc9a84130b748" },
                { "vi", "c8325c0d35f8cd4012075dc4813ea136a9dffaa8587e126c1b7c77f64e78775db65b9b781a3dad81970e1673b2db12fadd61afe2ede58afc9c856a5f8d560356" },
                { "xh", "a48f6785ccc7bbdfe2d57d0895bf46fceee4d4bef2207a8163213e54d5cb835ff814970cad977c319b267802454f54dd6d7d1b2065fb37c2b4d26ac4e79a12fb" },
                { "zh-CN", "0d0a24b5d23af42a13a67f8ca09c1a3dfba8d2f488f33f6ee0b25138cc42bf6ea049d7b38e424c165bc1d7a91785f78589e04dfe4671e324efd233b734750da0" },
                { "zh-TW", "2969a1879bcc979f05e8413983011eb9ab8aea6afb2645905eb2799a63abe9a28d5fa9a9ea4a600958512d7a43860c035f719f3c8c677a3663a82d64cb330210" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/144.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d9594805e66db617b0e964c95a18fefef9398b563fde26632dccce47d0f922d29e555a83a5d521eea528c895e1facfcd9b3ca2148d4729786a0fe66651744e2c" },
                { "af", "454ec64c08a118bc84399b7b40f4e900b26c84540e0d67c5bcd210226d85a2f8626895ca88a2259547828605ed7b7cb50bdc7209d009401d55e506418536c70c" },
                { "an", "76694bbeca8da7a9e79a88ad27ae2bcf324089b971063a35f2762a42a4d16af5585468d0dace692a4612c762bb0ee3bdfdb7e176fd565d1b8c7df2743e8d5577" },
                { "ar", "444d67f7f2130cd3c49971d3f9a0c7d3cbe4235eb26b0022f57632ccb6adb31ef3f22ed7ff907defad9141f01c0285d2edf82870bd48f321c9344806d94b3663" },
                { "ast", "3163ec5ef7e0934c76ff9d8dee9e85f896b6cd1a9888dbe9310955259a863df4d58cf1d640614afd2d5bd35d872b9a623a38638d7b57ceff65bcfed0c47a5eb4" },
                { "az", "115388d4d46630205c029fc000f6d091c8eca3cd2d0dadd7b49f6bba5f08c3d85f722bf2b0588299b675239d4591bee6e63176df11dd221a047b7bd67a73061a" },
                { "be", "a3c0158a8cf3eda8b1b78a85d1440fabc983bb2caf9aa0b41c46f6613a6bc1deb1041239c49cdca4863df0e37ae1001c9080c6baedb492e5d084c597fdb04110" },
                { "bg", "ec18a85350c68a9813d59d7b93c42077958c0dc2fb47ad42eb628f14ad57bc1c5df111dd4ba66b6dea2be3aa53014d99f401bed363d140baf29b08b1ae1c2b0b" },
                { "bn", "db90fc8265294d811e1e58ebfb00161a1d67141e3dc4543a5f150a126bbd2f484dcf551f9e6e395db0fdccd28553c3105c1bda9801526665c7ebfd4ebc8ba20c" },
                { "br", "b89a1c196d512843aaea54cf9bf1ad23a047118979761cd54eaadf62f03dd4e856b2d011144d6bed3bb1fa0804e597a7f237687afe0c467625c00064c7171a22" },
                { "bs", "109d74d270dbda197e02d06f1fc2318c60a842399a2e1aa64c58877651502cbe1a66c03e65cf461bca78f4790f80b645b3175727c3038df28f227c9f06e0b339" },
                { "ca", "3aa81e303dbf3cde0faca4fce1adb67eb2ff876e71aa93ad538cc3d6c7d701b2b0324c0e7177b62e484bb53a7e1962e520d492ef451e0ef6baccb2eb6785b2fd" },
                { "cak", "32c9154bad93cd8efb077f73497c7120478fa83d2533ffecdecf3b15e2d7120d4a670c2ee35e1e9769ac7b6c9c4b0a9b47c9c4f73c39a2d2825b807a90c35460" },
                { "cs", "fe340ce48597e5004e7bf742cac723e040d1cd78953a2d6a1b29fb22786aea6c77d600286893a6c1c94be57ca81e0492cee93562c81bda1f6c08a87e9bec8ab2" },
                { "cy", "c623b1c3d42cd0568938c1f4476a5211fcf13bc44e8fd056018d585b6d17ca557ef5eea030675d56ef76af4d72ac97e796ab501c41520076749f0bcfc95aa862" },
                { "da", "ad908fce4851b4cadce435e8929f612788467df891bcd0032c5d72d983788207d739cc7fdb748b6a0ebf84d2399eb3871b3b5b4043d8d59e3d8e5a9983cbbe08" },
                { "de", "cb5ab9ba50028d0e86fd589495bb90c4ba2d743a2ab97acf9281e96e0174b9bdf195b66bb999985f1e81618e7ab5f2b53e1cdf6ae9c60fcabee2c02e147d18e4" },
                { "dsb", "590e9fa7a633a717d28d4169784eccb7e067de10ead75e555f48b5aa05d86dc3ec7ff5c16185902f3a3786cee429d0e0e3fd51cc29bfd660320d81832b4d8e03" },
                { "el", "48ced59eb214f7d9b8d2011944f557cf9ff8e03b203d4d3c0a983c5c562b8e6356542020c6c0f846b44cb21cb57fa228a276edbd756ac6f79ab487a766305ae7" },
                { "en-CA", "022ff61d35cea743b289e6b5f19d541cd6f637b072dde81183d86adb265972e42c615cf138113e014c9d4a08e2f3ec31df7dd114c461cb508661c20b1c5b1667" },
                { "en-GB", "92e721b993b73e3fde5ca8719bb9f2db8de95b7fb841762e8591aefb2e129120a715573665e9165f6a87ce13c97e088177e15103ffca35b95f7b592a1b8c259b" },
                { "en-US", "7f040fcc5809daa9ee859e902db5c02a5db7c4ae736400d2390fa7e993ab8ea3c90416165029f574a8a83ca86b663a03ddf2f80a50e2d8a44101c2447eb9813e" },
                { "eo", "2aff519b0d5454b9cb3ee1ed8b4e652254c994047f3cbe1d4d52a78c84f035c21a0c3e5726ddcaad8ad723d8532e85d26318e16f224fa107d4fb45a0e5a6d9b4" },
                { "es-AR", "87eca35e5ca4bc58c682076f6dcf0f10010c3475491ed54e343cf9d28e135d4ab5fa4415712f504f58cdca5c620eba55b7d8b48122e87ff01e3cdd6c00e64526" },
                { "es-CL", "75723214d3340e9bcedd3369cbf33a5610d22c086e9deda723b1d71b0963b677b678208446da3a4394c92047284427aa504a5a81040075d336152e3e26411108" },
                { "es-ES", "11df0c916f8e4dc4ecb96f2decb2e6711311c817d40825a84212497b14829fe5c870a1eff56e27f337021a53aedc9c8071659684a8613cdc3c1fc0c2d064520d" },
                { "es-MX", "b10c5e5db858c7fab087e4a07ef60aea2f1d69c038501e0d6db9c257d6b5066c0bc15b8faf3a10e7aede2f2f7f409074c6a56f9db16792fa7da7ee11211350aa" },
                { "et", "f48a5f6fefcb33763c0f3f4c363abcc40d1d89f3aa1197b95dc68c737daa5a77dab393a367986abc6725ef70260b0dab00eeb8c7473f66131825942a47f14370" },
                { "eu", "fb441efecbd5af1e81538b945d5df5444c9aa51ca8a63be37f39c7929d1094ce24a08b44fa4c75fd212377b56a9b10837daac16d96a0f19a0840f700099076c3" },
                { "fa", "8b0e1fd71e49edccfb803e154e670f991616aea722ac1d95ec26514682146e0b94ed79f39e14344aab00164e6bf97316065317a8350ee7c9b4fd9ae2c175096d" },
                { "ff", "445c5b7b9cb1c164f1f2f04f59f115ce5b283efa5b7d9d3bace22050d2629a77e71b6897f054245771ab300c450b3cda0598e793c97d5780eb2530067f6438f3" },
                { "fi", "e43b06b058ffadd8e1fb999284bfcb385c092b01c8c86921810954505f8b48f6a1997ca19be5ebef0d085e0c4ede4055689e58e0b47c67d166c16c278444139b" },
                { "fr", "5e0ed5b2e57fcf1b3f6f08acbb9dea44dfe3a52348b4585de28aa368a4879fd51187667fa6a6959afcf4d276729c3f644677acf10bf143fdfea4d842fa7f94a4" },
                { "fur", "335cf7a5e5bc7dfb0d9a1ddb1ff43a0de660694c85e0bb00c3011a5822632d53a94bce0c90c1951e1124f0a62ab4f504860237764551721a9e051ba99d79dc74" },
                { "fy-NL", "912eac7eb76200a3c4a65f97e4d7ee39d7d3fe6553528eee6a2f498f1a4a2a5e9bc6c80ca4cc40bbb3271f7acee05e044da06c298a9ca16caff33ec14673a6cb" },
                { "ga-IE", "e8f2fdaf08d326f6f56551db6f92a34c42f17832e075c6ea4822b4d0068ac43e2eae06c77483f28c180efaa0e236bbff6b161ef74ccbf2fa4cb9d6e396a18308" },
                { "gd", "5f2b47263df5db0dcd3648ef249013430934018d737feeb3e20152fae01e4f8e8ee02f25c3108bc6491cbc03a385764092dce79c69895aef955027e2318c4760" },
                { "gl", "c32902cbc6145553d863824a5f1086533c4e8aebd13eceb74f38e729c1e81d609c3b6ed1d1a173aaabff582ca8349421731ce30aef631d4444a3b15cb6eb8934" },
                { "gn", "8849da0d9f5d6876142437172509ad2f8cd01d67bede26796d8bd520593838b909c94462868af90d86967cda1065689a6ec4f0149e526c2e7bed9c6e5719ed7e" },
                { "gu-IN", "8e2d6d44d7d4c25c6933bec42da93903931203a8a17da041e160441956b31599df73b29667b9f141691c58e51a90e96ff5796aa1e83884fee6d73a36dc467bd1" },
                { "he", "3120dee580adab89959f9f2c67c85aebbf0b7c7308601cfe1e6ba161fe650696ec15c23fa0ea3d6e5fc82ffcaecf49c6bd5eebf5bc7ef315c5ff18867baaeec5" },
                { "hi-IN", "9d85821b0e92b9483ff6e7a02652fb728ecbb89cf5262b0ec7a52bfb184e537dd11f08a1ace7eb3ef5b515120b525148466e65d6bdcd936c454dcf53d0303520" },
                { "hr", "947dc4fa9b852194c3f18ec7d6ad4deb59bf409ca8c6bb50a5e8d8d2f2d3f645e1f056d04325338a8abd0bbc22fc26147a6a53772535e1886c7adf6ec19c5485" },
                { "hsb", "5f8f60f973d38d4b550c9ee6e620bc8197e22938fd1696b44f5eac8faf0aad16182a48e4fb84bcd2ca520c9f20b734d6328a4196d76ccadee981cd30c0287ac5" },
                { "hu", "71f43e2ccd82107dc9c4c2c77e7c1f82253d1ceb4312d3af7935f31e38674aa6e71ecea28e79381fa62bcd8525ac272ce01f0131868b78984c4f156ec31d7e04" },
                { "hy-AM", "f6a761baf5edfa40cb6767e7ad2d8207adc0a3c254f708d26fd53cc1881b13b57b38ba625ac910206818f36c2d20e6ee5c08583d6d90e037f75c151e7f699014" },
                { "ia", "a2680c6aeab2e1e105254ec07143b6929c4a710bdb7e6dfe40a376c10ae63c4f017cb983753175859b4ac9d7567dc04585ad1cfe143918ab6d7bdf65830b5a2c" },
                { "id", "7bff599fe7b44b9cbc0a2fea97d6a728e8e520233516d9b86f4e26f033b3f9ce328c7fd140436e6d1fdec8b9ef1fc1cc6e17563d7c315721527ff62e07f689b3" },
                { "is", "e08d8cbbdd79f4b2f75347134612c3392868d6cdcbe74aadf7148498e21a54c3e9e62aa13368e48351dac2ef2f6c3196d209466ee2e3c760a976f7473c935573" },
                { "it", "3241156e7f8aa9198825554f3f8fa4afb067270fcfb7a87688c169bf26ba857cbf98ff52d0d9d88e1cc5faed80322dcd041217530c5b407d3f87b0a259de16e8" },
                { "ja", "ac7d13f34e00559663e2942ffdfd595ceb2705f87d84b1b294d060049fbef4d7e0c48b063905799ad181b4fb0852c889374d3ac8744f6e2e19ed5ef4091ea52f" },
                { "ka", "6991c81fca2a75db0e1ffda4c5506650bccbd91f6ebe82f6f21cdf9831f628e5376a86debc11df33b45add3ff755480269b2ceca32c926c2bb5b87105450fbe9" },
                { "kab", "6ff47eaef99c070f88c16e2daf18c0bf327314a9f42ac47fb003fbdc99888f949029e9fe0d41eda809e20a8b855d8da0178d0d9da56fffab3ddaee238030f4bc" },
                { "kk", "45b85c5a3c6e43b6d1d684cd5ae834c7526e227c47e517103916a9fb9497742e018df77645faa5d77e8798d50795a96997c4905d15911f035e675a0d31fe4d17" },
                { "km", "5183569f134efb2f5797ebc0cd035da5db5eebf318ff86c7975111c8d8aad7f13da0588e49dacc94a9ad2951f837af21d358e90bda7387df001e7a413dedf458" },
                { "kn", "eadc00e6f9e8ce4a801b8c91d706343e8ff6cb448e2c2bfec4e7fb2b049cf76bedca765a1f445d8de9aab38c5af5b0fa5008305cc7c8c68afe68c9f5717752c7" },
                { "ko", "8d6bfc781fa3831bb2c3a3f22c6d65eb4c505eede08f1902f8d86cb808985cfc172fa13727817ec5f5ea9112a1e1fa28f6d00c24336f64ed2916cbba1aabf969" },
                { "lij", "0e500bcbcf4435fb9093a48cc75ad82bb4da60c81265d5c7051cef01a9a554aca979b4e087fdada3c5ecd937196817a2d16b8f4c943e90b50dc30cba8f9abb19" },
                { "lt", "3844ad8762dc2f4790a4d388e8e1375d4836aa4f03547e9bc5bcfe03e56a5f543845eec827100530f1dc5d060cdc0f8a0d0bb8d4065d3af2518e74dafbb8e67b" },
                { "lv", "e9eeb3d1d4435777d7ffbea4028617cd7a61b2cbb85f43161dcea2f77fb4afbff14cd61419a039d28815dc2beda36841485d44e72750b7ce5be4f64bb07141b8" },
                { "mk", "06728addef547c733b43837c167423935dca6990abb0b5bb6e3b9d06065c3f3615aa8473b98d7607a5fa37a6d14a7c58bd912b5368590810094496e6a87d1d44" },
                { "mr", "117ce2511fbbd453c5e7ba4fcf18b29d9869415ba67d07b43b3b320e38972bebca0bd9b9d91855a2be12462c14f6d90265c02fe859c73e20239f3eea777e94e0" },
                { "ms", "f19e3f1bb1e6c8d3cd0846cf7dbbf701fd7aa9da90090af64a1c56a807fb47a03b2f6a1cbf1438277b801c58a46d544f9fa93c1574f1bebb45ef773cde1f1cb5" },
                { "my", "6dfa07639ef3ce2db4f8323784cfe27d732db221bf11d08153fb0e0b9baf3f2f3f18ad3e30e229b8b5b3136b2c9097957f9a77fa43b2fb6f358e4262f3ec95ac" },
                { "nb-NO", "9b6a42ebb38a836e77e0bd80a2dfa394c966a6b9ed158a016022b2166d4127a1cf3f49184519e2d662cc72236fae3751b35765288f87fee461549bf2f1690431" },
                { "ne-NP", "1aa79cfa5d5bc42efe207aa7e30abb2bbd3d750fa57f6aa8873e93c33321901081ba3141c89746b5780181595486d28ea1c799d7911959344f741ff66d09292d" },
                { "nl", "d762004e445a6ff712ecf14dd1dc2b8597f77f67548576622627812e526c059cee2c4f7e98b279f3bf57f2c9381ada0cb89b0e4375fda8100680928daf0a2f1e" },
                { "nn-NO", "b27ea052408a4bc4663ffb0ce5333e9ab7f3f906ca09b882c4653a918ea66cac060f725465eba3ba349a9bedd27d60166aa79774a6692a60819f5b2ce1a50311" },
                { "oc", "73849987b564f906fcbe61a7cc618d1844457ab77f54042788f51e80be628816312518d59ea930a323150bb43c3cdba9852cc02e6d1bb982666732995caf5f11" },
                { "pa-IN", "bb62a5e8d77e7f7869819fdb8296610172577bf1288b81df14b0ab13da3e63c322936dedc30d59e96bf964d45357b0bf6e4212ace0a574d5842946245c105ad9" },
                { "pl", "f91b6bd5a972986e3605543e3d43cb3b6d540b6abe044e91ba22fc2e5f72989c9eade4e163d363f38dcde2d294e5bea252b59fb8738d965513a90f5b4054399f" },
                { "pt-BR", "b4d22fc9cc05c6364c3e33873a6aad28c7d2c0311d2d3995321dfe20db73d749de89931eb8e66531de736b1accba7ea047538d2e945b94355024cf6a465f77f5" },
                { "pt-PT", "5b8a4fc466b36f20e5e4a142e0aa9bd398cdff961711d9dcb0e1f7922d854f5ffad5f771cc9df6bb1f3e9e641cf3a71298b77c3cbc82f1d96cbc3535b542ecda" },
                { "rm", "0cec177b8624b1b2dbba40e45c28c62b217c957380f5b3ff463d473e5ac170ffc980c3d7c09ef028518191daffeea7aa7f6dea04c016abd015a6e2570c068710" },
                { "ro", "276adc7d8d104a4eeffd2e3eeab8591be97189039d3e7a5658c5851ad21aad4ca25a2d1e5f4aa6aa3d8ffeb761ea6b1093356f75000c33f33cbaee5fcff35f9d" },
                { "ru", "5461b7180f8ace1deb182b92c3fefbcdea581512c382e4b1391bf7363c9e1f1143864083e4d8202315d4c3936375fa9fd0117b0f8fcc9023623691a71d7adc36" },
                { "sat", "7ac6ff9b468d7b6c5e2c75032a73683effc2614290b606b8eaac89652db499535105d34fe59b00274f5a426165673bd1ee491a3eebd61ac57242c23ef26abec2" },
                { "sc", "22b6c3fc15172db104fd6ed4e4ffa20828ca3bfc43ea1e2c9dd9dff23b217c362ed621ec12fa74c2b8a97740e2a72a515cde5f73596b4b18b383f387279cfb2b" },
                { "sco", "070ed76fc555502c6c1491f5eb82c86ec8e3414b7ec540bfbe6b76c00b9de61009c48fff5c26c3b69197c5eb53e445c01ed14c64dbd203079dcba38a7a56ac95" },
                { "si", "3eaaeda279f0734753d617c6c43b36a641208ff8dcca8893799cb494138a3d462197d9db3c3a4e81a8bc6333aa66f51a7f4b8d882557f58bf7574e897f4371a7" },
                { "sk", "270946b2eb3c64dffb507b9aba48df79b9916e8374236ddfe8c16e2ba68f2af9d7454898cf5a2053781ae56e6d91da5032bc16f9be3f1f9ff6af68cd7b93d32c" },
                { "skr", "6cc3719ddc59866d0eb3f8428016adaaf82253bd7437a0e4e6dd2e600c8a83324913448af5e74264981a861739d6b7a99532814031136380c846718d1864f495" },
                { "sl", "3323a2a1fe635a2c0ee0005c08687f4e9923aceea2b34bcf2c1ba36b8c23c347acefebbb778bdf2f6913ddf632991556a358ee3dda270b503859455b7fa3be0c" },
                { "son", "ba0b0fceb2739a7e32daec5a3eb7be4c6f85e1825231b9a210c63dd76659a69cf995c9ea2f3e43d2a27b28768a14691c9beced65e48636011d6ae6ce4c06ab3f" },
                { "sq", "97192216cbbe1615a0fcd56cf5c50f88b9621f89732c1464be77f745015d3db939ac991b97e6ab7ba265225b4915b5f0a0b7eea29fb23366a4c256081a1b9e41" },
                { "sr", "c04b2bac83789750b2949ae37a241f43c133fb01c037bddc70560a1b90784081531d72a68299b5f412031701e8ce2609f927f9f80a50559388f8722c7036db87" },
                { "sv-SE", "bb528959f25756915cc0946d8318d0a8b1f4b44c7d41ab84e6a9b7459d987533e8cd82ca1e8802ab17bfd707ac0b50adbd990691010a83d2561fdd50e167063a" },
                { "szl", "17f2011743f958d76d8135a2b810db50a780e71fe8b330693bea4580131d00f8ead6b9c6b779563809f4d0a43cdefcaac1abe4c793d639abdda9f51be4348b5c" },
                { "ta", "7154e2cd23251d985a88c7a7d33dd6d50232783be9585f58e6be21d5a09edd97d2d805d7c67078edd5f882439a7d2ad3b285099af3d9573e6970b489e10db7f1" },
                { "te", "9c2c92767724518d9912e5b3431d585567ccbb581f4ddf1e9487645a86266326417b987e7646316fe82cdf3f490d4048cb03e94d0015b6e0b501ad5d95810867" },
                { "tg", "76dac2b38873f1787e5d8d78e68da6242a3afc789e6e9656e5876ee5ebe183d7373fd02ad125f4b80ad9ab057053617e90cf7f134e3c81b815f9da59264e1b93" },
                { "th", "fae7689b2f7f1b1729000dfa19b7c84aede0b35ba24efc6733640a178d4f6a2776ad8173af98953b796309b7c2950aaf47bfab5acf24eeb0a4f9de2a58acecf1" },
                { "tl", "b6616e1c6d8070af4d6d96dd6dfa833c75a58a133b6292d61bca20472f5703df33c75fa4a482bfe3b936e9d368c402434eb8da7840e6bc7262359c961f10fd46" },
                { "tr", "7d5d912e7443c4f97d9f3b32845c791eeae0546cd855db45277dddc0af1236efe6650d030d9d80f2fcbcb1a8d8fa7f1ca1833ba738989e2613b1cee0a224249c" },
                { "trs", "907de2214305f8e26bacccb1b8427b9d412865b85ce3581b09ba219c71f2f9bfa6f73968e50b8de26b3f37621ecbc3caaa601bd03e3724b166a05a7ef9cca0a7" },
                { "uk", "e4faba1e73e84d7381cdf8db8bf5e5f9ddc3f40315206cf66844f0d17b0154d6f433811d56e21cf2800dbfe5e4e7cf49f290a386f1f5c7ddbbe14511065e9f7a" },
                { "ur", "0e9554c04405d2b318de8265b35cdcd330bbbeacb42ed1f89f8b0d55caad1aa9a45bfeebc5c0b811828f228c94448204de854dca29ce31f6cd707056cf9186a3" },
                { "uz", "733f7803933cdefcfd24b8e8a5af2fae74fc21cbf1b15831b4e233c37678862dc81e74be4207ea3a566bd44540d8832fec75b9a31b7da46421cd0a8898eefd0e" },
                { "vi", "ca94cacd55e03df68c2c1335cfdbe8b7e2ab4ae5c69932d4190579c178652eab753085b6f99b305704a4e1088510dea0f27953fbb5a47a0f91bd7c97e91c9520" },
                { "xh", "e0767e5118e401d2569b0bd880513287998025ab77188efc20384f1f85ee7ed1234be87eecb89317b830e5a250fd130e14a846d8a40bf96e387de8f44c15cf04" },
                { "zh-CN", "b90e51a16d652b79c3fbdfe6f17cf34ba9d97552e9787978cd81dccbcdc90117d4a5778f6f334de9bd75cf70ec719f0f425d4717c18ae8c569cfbe2560e638ec" },
                { "zh-TW", "37f02b401ee6dae3d2c768c3a13a79ad1bc546b24f99e66279e63fb437c96590b042a03ed1f5f02af223cb8fedf74da0205053e5844febaccd4d34bf9adc03aa" }
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
            const string knownVersion = "144.0";
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
