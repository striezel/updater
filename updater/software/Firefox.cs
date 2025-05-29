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
            // https://ftp.mozilla.org/pub/firefox/releases/139.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "054c22e4256de3bbf52459b4b88681b57a4e6d90d8f22e905c5849fabf5cfc36b8cd7d395403b7843db6f4dff79a400b7d056b4d1d214013a0e3722b3402c5c2" },
                { "af", "50c11b02ae64588fea2bd38991f551c7cc41ccc938660914da7205acd1399687beac40c76bf7409550b5caedb8c142bac6ac2eac2ea2ddb68517778a6f61f55e" },
                { "an", "b256b3b9c1c8f2a73a2869c6be7e19609979e5130630c5d59e7959cad9bdbe922852cbd26064784260e335dab7a0f1eb10a2f23d6b6b68efce2e89ae251dc740" },
                { "ar", "73576414147784da4b2d19407b852f5195651313b4da234666c3f7372827a451f066e23d4cb62f6cd9762e965424d8462b62c46d7dc1a5753fdfd1976fd16333" },
                { "ast", "254ceffc351312a11efa5cf93ad38fdf5540e3921be6bbb2dec0460b3ba02bbeb6f526427f5c46bdeb0edb98d3356065a49521403e1c29ee685abb7970863a31" },
                { "az", "3c71328021510c06cdc5ed27a14549323f77316a1af7264f284b9c61dead59367a02ee882cb8bf5f3a706bb5010765c4a6f73b4900f5ac4c71031070dda14cf4" },
                { "be", "b0c496803eb7d83df98c704688f0ae22676945928610a7a15a7d2af424d2573b077ad8ddd740456116d9d3819aa289f046c190339f4f762933032d5351e0f24b" },
                { "bg", "44d49a603e3bc829440e9a0879eeba531fe6b1636c012f7407bdfa41a4b6194bb9b18d8b50a10019029ae801e81e18d7b3b4fff7278f5ab090e676464f2fd1d6" },
                { "bn", "a4c484cf5b96ec228adaf926d65fb12a07043202bc83530fb67c11f3850962a36cec5e0c64d9ac587a440fafe9afcc5cea03210b689fe3b416d994b4181f320c" },
                { "br", "09ef86a65e2ae72e355b2e358ab0e6ef008d41f0a03b269f561e733b30c5b7d9074554d679ef1ddb1794ebc5a19a0abb7ace6d62d4af8a362e3a2e9208d3d3db" },
                { "bs", "14bad88d60d956e86d4e08581ae0bf761fb6fe6b1a72f48c951cddafa5ed7353c7e544ea071ab118409b2b67dd6cb114b16cc2b25a84f3bf1d8e8665eceaf076" },
                { "ca", "c1e58eed7e16462511179135ff71a2e6ba075f42323967e4f1d2bfe3ae66c4546e062a506d0d4e6571e988fb9b9e462200abcf00631d5a5151c7ad8a1cafe9a2" },
                { "cak", "1c9ebd2ad40d5c2fb25894dc57993e98f73c43acebbf2383f38a5d96108fe08c1a58da5af11b56115c6b646d82559e0c66fc18a5e3329210e63584803c236816" },
                { "cs", "ca992bf99ac60f482e7e07ba05386c08f6743a6ee8a684863857c86495f0dd69386968e4fb24b00c03129616ee3d5fb46acb1e3e7cc8b8a4852258dc3a2965cb" },
                { "cy", "deb0be4f4ec0887f1883d34f7469242f05e948f63347c95b27a30b25b99b52d6af04831ceba7fd224e94343077653b8ca9437d6bf6e57dc984cfe0a8d8a049f9" },
                { "da", "a48a0841027889a8f3862789fee77d2cbb086e4c0f59267f09c74149b5d239ac309b1d7a247ab034262b1ff75195a14d9a1dfa779a1897642b20a2771792ea57" },
                { "de", "e14be049ab6fe894e229937d7ccf0f3fc3048c0143b86232e8d1e8bd394f958e86f621b435d05f4d9f762b60ca4d6f4d446a745c6cfa21e79acd84213c109c2a" },
                { "dsb", "4507879dbd0457e7ab8e89bd6f72edcd982bb87950f071e943e0b26e674ad8b6cb64077c2497c291c451780dfb361ebe9e43459ddb7af7472987b7686c6e71a3" },
                { "el", "79198e9de3bb1a173f5db3cd55ac27e9a2fb24cb260fe95ed6d4467b12cf724a2a4fbccf48e2d6c6138b02c9231e7829ed995f46acc43ecc6463e6e33f77e481" },
                { "en-CA", "dcdf5e117b7a502e0e19fa1ee15f0603147ec57bed6729fd07041ae0755ed4765a373c86bf8886b069f4893a6de6eb413e039dc670d7d6bb0d42d33e0e3353e9" },
                { "en-GB", "41286eaf87d7d867342c1941d219fc505c0a0f16e2eb86d0a03677a464c7507523815ecb3c38dfe77cb8fb9a9f5687e480d0dc3ecabd9f06f6c2eaa0a774d662" },
                { "en-US", "8cde00126a4f777f7bf6e9585e36c9fb2a8317b3a4aeae36048084cdde4b937b87913941dcc960755626f4247366c474f46997f2ae3e4071f844e3ff1ff0b977" },
                { "eo", "b8923db892d44c22963059e9743dd81b1d3814497aacb908606ef9b570c95fbb2025bfed1d5fe0eac35f5b2ab0b4188bc38055fa636e514b33b2ef959a3c596d" },
                { "es-AR", "3460fb9ee67b0b25a9183952c2673ef54bfb57a10e9c53e37d27efc6becbe46f7ad6d1508af9995b9d44705d01fff899f1b616ae3eac32186fbc3e547829b566" },
                { "es-CL", "259e15acb49b5c0059ac54a1d9e9522f33d79a1a8644015eda5fbc39f98fa2d71849fa51a690d224918a6567d382fe0510eee612bd2f5068f08f390424462b54" },
                { "es-ES", "8b0658a4dd9f2300cca94a1e7709411e24812aec682dbba1c4821ac9b4f2ce339adfae5c5be73f2f2a8f04f9f540f9c5f7c4694e81bd78dfd6d7e0dfc5e24956" },
                { "es-MX", "3cdc10fa1d09dd154fcf4b6483a029cd345ddedcf59df421009499034fad8fce0e1b62bb1ae8dd504b0c0921a755cabe5336fd2e13da6127e1d9d9ccf7446c91" },
                { "et", "085243745bb0bec5d93e9dbf16623fc57e31a9d7e157a75068807079b76dec4d5cdf918a387326ba1716ed4f0f1d0e5c32418654f3c9be27ae1bcc373abd79e4" },
                { "eu", "07aebe32b873690389f961254734833500022dbb0275d77b895fc824d6b8f3edd0f363ef319ce05e45be899b4606e3d2e3808c2434adab9804d1fe713e3dc6f7" },
                { "fa", "67f7d17b2867776d3f0d16cd5f90bb5f729bec2f5afce833e1fcc2d38e8eb1ab2cbe47ace8afa4d5a8a769ef14a2833f445eb2db114b2c2e2bd3e13595b9f016" },
                { "ff", "dd74de4f129c4cc4a5f879da3ae958366de4d087e9d0e7b76bcb6d68816fbb202bb600ca566800a4611d918883245de03e9e403c9bfde3d091152193858ac6bf" },
                { "fi", "6b7b482b7a7a7c021edc4a5d01e6daba5e8b823ae17ca960787723f5cf6a6d478f1b0f28efa3e3f7c608432fb16005a3736a6b53d604bbffcd757ab03ae03752" },
                { "fr", "d4cc68491654248dca4eae0b2b8d8e9fb757c659393f399afa060cb78b3fd8133e881c34b6d7aba941fd0faa2042bff62b510d7687c4f729e1612472355a7d37" },
                { "fur", "197cd30ef0387dd72ef7c8ec1c652c260d8aeff4999456a0670ff9adfe04c0a9f360d450c75a605871d9fc5605becc8d19af0735c5d1a1c0a4d6fa7ca2ae064b" },
                { "fy-NL", "28044f33565584a1d542e87e758bce640afaff068c1e73e0f368f1db3e2ef11967fb37c913a55900c92df5c86cb9b25f27eae18119c2ad0ceab07551768e2472" },
                { "ga-IE", "d3fe7ace2dcd31d67a0aa6692ec244f3c3ed39fe67a83ba96b8741c140685cde8eadd489ff2ef27fa65cd9019fb65652e4531eb0f1a75999fb8eb58895ac4c8f" },
                { "gd", "c38ad53c70e1886a62591b2fae9d5611333e5536589a74d60d210353530611fe6131a9d615b64c03bed0aa2b7d7461b1040b5539478c749b0fe8537345063be7" },
                { "gl", "5de4900cf590da34a4368b624bdbc1cce341d6d56d55c1af0b31b7b57621c6992465b906663612e96481747f55dae9a669a892dd8efbea1dd877654b83b1463f" },
                { "gn", "2a7efbcfe831e61786dd4ebb81463b3ac3e22b85dea6d150b7bf1c029d2f05c038ff90e4c19bc235bd5930ccc2b8cf2db3e78793a957bb0eb5f81901f635ae48" },
                { "gu-IN", "b6d2d4ea21f3a7ec765da7fc81b6405f2481c88c3c856845515dc9cda57a95a6fff217631966c17b3bda379ceb3893b376199f9fefd3cf11d59aba6bedf38b47" },
                { "he", "9cfe69f504577dad565403dbfa3601295ca9e7ae285d4a5df0f60d95de879e017e0f2b941523fc3ceb96cf88d3f96dbd87ddb4c990bd3593d5b511b000bb7741" },
                { "hi-IN", "235d45aa90ba94eb062e982eb0cb33454d1d56112730fe32df10622f53b992016e14046e89c47817d413155f2dd3b31a9eed3ed559bde20cc174ceec4f70b0a7" },
                { "hr", "247b6063f48d3479f933d547f3ae356fea0310b6ab11007d08df3940963f394025ababd3285f66216ee2a78618bd3d68132bb25538e12b52913185d960436bf5" },
                { "hsb", "0291b095d1caa62fe58905a3da595bede375d63cf1f1daafdb543350f43984b67473925252c14d13050a40cad110a25197917a1fd159231e8404fd363fbc9f91" },
                { "hu", "591ba1539d5d396bdd0fa0be4bcf685ca250c1b5a33b32a979c6ca55b4313e4995e8c8603c154451455fd235b8a80b3634b3a686453b261c9ee57f941fad12fe" },
                { "hy-AM", "ce676ca0678f0c4ab82f12688a2616b9522bbbad84e0668cc86adbb398b763dd33336a6ca0215efc68a44baae05e5f1be0b6eef086731ac44ce66cb8975cd720" },
                { "ia", "457a81c0977013a0eb523cd2962818eae59a72a4c3553668229cc275828f0b9424c9d6d4875b23dcb08bd1fecf87f0f7e48963d8d6702bbb6f442cb1a7ed16e5" },
                { "id", "59fcba15a5a58bdacf5e9ffa70a712b319741fe0579944a5b2b1fc138afab4d792303e61e7ed7ae17fea660f0cd6735b3bc4f53a869457a0e2daa1dec8aef69b" },
                { "is", "298872e2be53acc3f086d576264be7af0fbb886b5b01d26810f4ad123ef3465130aad5868a27ea49ddcc219530514425497945b4c8803a8b2858e89cd617f5c9" },
                { "it", "e7ebdecb98e529e67ffd53a60b303f8a7dfdccecbd880dda4bc582dd9776f25c7fddc2687e91486d2185fee42e60e83280256494e0490e363f2ebb640240fbc3" },
                { "ja", "4fecb7dacdcf0ab0700bf5f0bcd58651271b6bc0d473807651b2971b47fc4124b45123a9bd48c238a9c08c42fff347577a8da1bf74553b9e290518b046a83149" },
                { "ka", "889a902ffdcd8d5ebd6dec4a0f5eba2d01dfeb2f56a6586b8804d68303999b961f8f3db5f875575f19742b1ffdb4b06eac0376a08d1bc71857a4e3c6362a9ba7" },
                { "kab", "c28bb7962e3408040559e1696d7afd30a80d4397e3c8c7712c8ee3246c0862a38917182a702267965da94d6d2576d71ebe270547e285d0068271fb06304ea6b2" },
                { "kk", "d34a75aad03bb432ef8984a0af6e6d1021a3c475fc5793714f7a35d213619418cc9c9322f5ad6105d7790daf6b53b836a2138eaa24ab9ec3c7cf0116700b353d" },
                { "km", "f9ddbc3a3cdc5ec3f8a608deb7445941f26c0b283873d606bf553d673269f2f016dfdbe72e23a096a0b42f33a307354f4723f1bbe4bf4bfa7ad177fcf3b9ed7a" },
                { "kn", "c3e90c87346d46e7ff8014964d0b00a56dbaeccdd0ebaa9494e1807164c9dce2c6815d68b3d81c1e7ce65ddaac7f62a2fa509df50d44354ef5211077417f4ee7" },
                { "ko", "cdbbbc8a5f1854708bc7cf6406251e6ad5df2828ee99e8b45375e425142b28d736f41cfc0d690630c8c89d2a2016efc95a51a73375426340a765460d87899e03" },
                { "lij", "26bdac01f968e97f40261878bf31c1b201ed1b9cf73211cc78af4d59d650c7c91ab8346f7830d673a24674331f599d1a1c4493d9f02ca81eea3ee4f114f488c8" },
                { "lt", "06dfe3d910b41029dda3595ab637d9e00f40242ac85454fcd3cce5f206c9f588708d09372fcc3f24a0d677d346811b0ae6a9ed93f2311cca9b651d6c01dea1c0" },
                { "lv", "f7e0cfedc2dd3486e987b30baf979a931011e48b962ff06c24909aa592f532c167ca4a69835b39fe8e97f9178750a0a32321d0fb6de2e26355e5c1557362568d" },
                { "mk", "7b7e571e0303d35d65b4bab358b3bf1d20d550a7a55cc5181ce7fdaf16fbdbdadeda96dc529d3cc98c9894f5f7cbd660c4edf7ff4b4b27dee2ca8fab33653adf" },
                { "mr", "39948e26309555eb3e2002871c0b0d2f0b512a3fafb4ce01eca5a58cdfbdf11b5eaf53a16a974e633e85bd5591780ee54b70d75d27f49a1b42606109be40f474" },
                { "ms", "efa350a2b745527b9179e6681d00ed1542c601609d02e418de88be1d66fd9a9464e65c9b514b527da69d3b98942304d03e26b9cc2d713868fa633608d1699167" },
                { "my", "9b4f51da79c23819766d3250401cd2d84228e284e66e4b7a0a12e3a1a13c8fb82a485934ea5182657ceb906fe5b24b772d993a3d14f6691241b61355d5cbbab3" },
                { "nb-NO", "8b8b45e73665fab060746efdbb0d3ceb98e79cc745f1f7d4c0756c0cf74fa5904cb727ee9f711f33f4596411a1ef7f62a3842e10962fe016c92a9cee732c3ab1" },
                { "ne-NP", "e4a8d4d0c33b4f1ff7bddc61e93d53e4aecd3e7d5f3a38a200c7cab384b54b24346d57da7fba35d8773be7d5672e86e9f84390a18dce6836cf80eeac7c31e551" },
                { "nl", "499cbef3167688e49f469e4b32dce1959e6520143820180690c7b6e7a2114059ea9f2d1b979a3b81bbd7a6003503c957ac2315e75519e8872d85b8e6ce370a05" },
                { "nn-NO", "f7e8c86ba78e9578d56515dc7df53d4f45e3a73a8541c1abcfd98f75fba695c6000ba427c2b67949b7fdf17857b0e3347a600012d72d6fdf148b6f56533af3d0" },
                { "oc", "7831e2a1613011d3ddeb9832d131770ea78b5d4534405264a672e065ace6283be920660a617e1860ab3a9b532d8f393756cb045474aaf6c0c716881ba1d08364" },
                { "pa-IN", "c3a8a3f4ae96f40d387ecba871e4f45d0bf1ecb2ef8cff35b62ff52622992e65be39c69d18a8bcde8e514b26b8320230f986829cfd505815578b8ec740d821a9" },
                { "pl", "ea06940effe28ba912b61db1553396fc50b95dd0da0782af22d1aa76a63227c5df52dd1528f5a2924fb8247d36ef622b52a0559186575aa413b9022191a0d2c6" },
                { "pt-BR", "3a01bfaa7a45dff43ce1f76b5a419685eea74b3f7999079194db528813faa360dc9c7fe0b14691e8b4ccd0520dc30be870a582b6e674b9ac3aae1f0700ad9f2f" },
                { "pt-PT", "36ea15196613f3a35af9b8ccd6a2fcf1d9a7ebaa7312dca50ea12e64c3f7aa6418cad033963aa50c99be73a8412f0bf5372b78f06837aa989707644b954833d9" },
                { "rm", "cd8f1e80fdd33c8f41274df53ab3088a4b6132312af98426750da1cf4844876ad2137084a939b3776bf91f200b3b7f6d8865a73bf254b3a8b352f8fc41969ce7" },
                { "ro", "225ffa87feffefbe8b4d699359132b3866ed5bb66d85aea1e81179f33f433a6730b4be1e6006e5e54592e126b4cae8b68c221e25637a1f27b3708fcdef5c86c5" },
                { "ru", "4c705f1188314c2e2b6d0a216de4ef584740425e266acd64e6c4da8c147e1376ff248fa63c022fa936e559d16a8842af767287973ff8c6e35780dffa8cd23392" },
                { "sat", "d86bb8b42c45b96b804bf676ac6b0fe9b5a3bc2f4820a1746f0ec1da601363342f425e71cb31a380e6e9f9f040033a39a86038743c583122212cf9a3721eff82" },
                { "sc", "6721c7b671a87f4bc19d3f5218be17ba0698625b0b6d2623905418c59c5859521bc2a38630fa2ae58573ac43ccc5bf840763891b098e5f2d7af91e790d870a55" },
                { "sco", "48845a2ed329db0cb8fc533bf80d03cc83440fbeace307f8265e558538982d7c47e8b9c71de5c2bf967192212ab99896daf7b6c85d142fb2dd025a7ac88acc5b" },
                { "si", "c89755a3307155efb6d3ed9c46b2be0209d468c99ce383cc6e810c5cc6fbe13c99774c8f07061ef7e4e27ed0e835a0f59d6b9c7b03f468e5c41803d9a7b9fd8d" },
                { "sk", "c4cf0e635069d6e1fa3c622bc18a3881f71e0b63d9a1d3aecdea28ce64604718144560491d317f08bb41856c93e5b5a83d9b6df85963c287e2b4570a7b719f97" },
                { "skr", "df7995d6f38683c6d86e2e2fe0010d2c21e310a00057ceff3fba67403e68e9c62e6f70ec054fa841f8b02278a2d6e9fe6f46b21343052d484eb75c01364d4eb8" },
                { "sl", "9763522ed4a28057cdd58e41433d9f7054e84f19f429d8ed93e434624fbcca16f511bf7a028c74de3e3933c400089277b907723c7c7eb5518f268b9f2455ed6f" },
                { "son", "678b5772a60ce380f81efac82b5eea5557f276ae92f16c0a8bb6e489eed4e674be96441fe24f036f95a715443137ca3145f80be3ea6f04ef1623cf7db1478fc4" },
                { "sq", "e5d67214d76696bee3445e1535692b031b8eefd22b3e7ee81694b35fe10313a9ae5aedcdf4f276fbc0837c2b582e58e6e7fcffd000f14312cc5a0e37b9219982" },
                { "sr", "9d64fc5e04c13f3aaf9828ffa0e7fc373a408d247dd8c20f0fca5ba67be521c60f635a76ddd0628d1bcf4f2acc09252b7dc2572ef15907aff0d5cf2ecdecbd5c" },
                { "sv-SE", "795cc0068cbe62072772258807109c916a8b9b9cc0dc254e4d12c6f458790d42d8697f8317ffa20f111627ff339cb3d21382e084f11d8b031d9db22839ba2900" },
                { "szl", "d6df954f30cd3ec975878688df9ed8d2e7be8803f20f5e5d8c1934a347c3c9f868693905b3a2cfea1dadf09f182694f5b9c3baa315392da4843ae0d309aeeea0" },
                { "ta", "2ded92c8ac6c39e8cf357d589a40482b22cbb2fbbfc09445851df90101eaf8afb83e838f1610331a8a3a870e4eb31ec8d9c05123e0428d6c80c4e128a35bb052" },
                { "te", "d93271b3ac32e352833c2d9156da90c3a7a532c32ddc21db90b8cf8888f91550588f9f21b33fb6978859e23751868b1651ae154de00595ba9d0c478f178b5cdd" },
                { "tg", "d7848f9ff1e5c5778cbb3e36b496e80b240fdd570f6e7a759b2074c40dea22b7ca76c872cce2b31098f1550418d6f12ec5150d8e9f0642897eb0060c0557a3aa" },
                { "th", "1e096455e5cd2c4639d4320d140bb499f380c60981425566f3d767006235d5bc4a8c3863743d9a521ab9ec5d414afd934e7b4fafce994bf5f96b5987ffcbf1e8" },
                { "tl", "dbe8174779b91326f567dcb741f630fb8607b324c30d1a508c724e5e197db2133935aa49b470df74750a85121e1269e2b914511c0ddf97c581468a7d9a717121" },
                { "tr", "a1118486245e49e824ba372703884e49ebbfa8f5fb09a07bd027437b76c36d3bc740d6c0740728491cbfb07985722ece0454b685503a85558abc189a47818c86" },
                { "trs", "eaac28e3468c7b3d4bc56dd92c67fb259e8b47d9cf8ba17dccc2c61d23b8e2d2c14903ed534cfa8fd556eb03a0c2943716d73a0375eeb04212494708c13b3efe" },
                { "uk", "899411b9936179c76c8084da668d682f85dab4f4e73e0468b5ba4d941b10c302bfc471e910454adbee77d3f71c67b50a96544a26f9375dad5bfe7a899a1d4ae8" },
                { "ur", "af3d976f09957a60bc838c53d970793c8f535c84986244ed9b6b44ea92c056e8511dbe6321991dbf0eb89ab7ccf232843771c0ce656797b2d444006a9f2a5c09" },
                { "uz", "8f772efab4fa9411610498ddd3dce105dceb727172d734c1a5802967b5443fd15fe615a2f138bb42c4e7553f92579247bd63c2eec3bb8e9eafc6cf0c98f098e9" },
                { "vi", "31306d640e7b49d8b0700a303f02e068e6daf3d6da78ebf335f6be5b9666ef10c1bbfb9fe9e2ecb0f6cc28c75b97de7c79740ff1deca9899b36f703e71781bcd" },
                { "xh", "b8ad4b6b75a573318a4d4483ac43d56c4a5106ad7396fa646b366db7256b738eb9b8c4c6678037d5b90cfb4e66bc128faca109ba54e6429bca5947f5248bdc0d" },
                { "zh-CN", "b8e62e185058570879cd40e257700140b10655ccec5ff4a0b1e6356b75af4ec628fc343ffcdbc89fd417840368f0757df023b6e7ad128d8903e4a63efc927ee3" },
                { "zh-TW", "702520786daca1db30b1c4ddeaf9de7f46e35d5b3f283c339b35e92759af7ca713570bc63839f6db8c6f1b3e7f54ff9e2c043d9f84391287ce30567915d45b08" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/139.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e6a6f468a8c9a62d86a48352828a5fc104dee85ca7c5047a68566e8143536d508e5f2af7967a027188e8b6bbb5dbd705bc2d428b421f7d28cb8994219b2f6e97" },
                { "af", "a95836ce0131690f7ffaea2bb4cb6bb94ea598e319e2ca65a8e3c111b65d2f4ff0f585b089fb97df985548bbb61a9f7fcaf2c1a23a3e4ece305656dfddfb2a72" },
                { "an", "f2a0921d647747fa00945e110136449d6113653c436b7483a4b0c84bb502156a0d1da30e1b804e40eec606a3142883d0b01275eb35aff060294e090ca3a2fe02" },
                { "ar", "e0ffd7c91de1f705a1568372ba03b8eacaa08495333e63cacf8f62bbc5176ce432ac14247e1b72facf667c47500e70513338ae5edb1badfb636bf90253f4cb56" },
                { "ast", "a0d004cbc03fe4ea790dd2ab4d68d4a4bc1939ad4502750d31be05eaede249f921f94554e3d824a879794b741fcbc6513e6ee7012932c2f5c4e5b9930e4dc972" },
                { "az", "b28e244b25ac3564142f801dec93ff36c2e0105a77198fa03f995a7efa6d10de27d8ac80f4e3beb39f014bbc6959635ea98b2be536cd21adcb5374c9533308ee" },
                { "be", "7122598168fe4b4e47792a8bb1109f9cadd5cab879e761a3fdfd44eaceef0c3dc7b0a19291f960fa09c323fe31d7d21c96007a70347af61973fd619d754f2ba9" },
                { "bg", "c9a39120252aab41d7dfdce0931b4d78cbaeb3455564ea34707353e7ac4e129da9bd3f2c3ae2dc927744fcdea5d07523fd7d74fdb2778fa6a5dbf144549b76e8" },
                { "bn", "749b271d9cec17618e2678007320a1dffa5465d301080332892a432986e9f77d3ee7ee6eb27aabdeab8635f1a0694d62cf8b8d6a98ca2a53bb0f18aec8645bb3" },
                { "br", "d39075e0e8f796a1e77a42fe156f28b89119b9e9a8f2efa97cd2297019cbbb79307b5a16048be8810e8e1e1d974faaebd6cb0bb060f07be89204db9bd4743b01" },
                { "bs", "575887cb365db8a2b396186b158d2499b4e5026ab986a4296a8ff404d6903d8f7f99250acb80fbba87ea0ba9184ce0a32426345457610d39137698424edbe453" },
                { "ca", "d5229769bc8e4a3f76fdc3e775138d24f524ded50c0e957acef0159989b3ff16885f3cfee15cace2b1a58c3008f066e576d6b33ba61edd1e731b0d1ca3685e19" },
                { "cak", "cbd1d058c19cb3cd468a81bff33e2bef7e3bc87699344898d3cf6c9f860c3b3996355c5ded7a70cb6fcb10bba1b2c8a1ce5cc2d504f6ccfdcaa0ca3ce09f367b" },
                { "cs", "9f1e8e792fe5be990ab2d10c46fc7a8506475aff5ba7c381250c3d17d7e62dc6de539c0618261a2f08ab6a495c71e88d824bf6da9e6f5a3f2266d2d45dabb5d8" },
                { "cy", "a435607664e23c8ba6dd291ebf0d543a1e1ff5df5079278919cba332f6644cf1e02b757d2a67f5a240ddc8711777c79a3b3da9e4420c97dc90f5b53a29d20249" },
                { "da", "b70d774d99295fd8574add557307f8a0d3dcf735881c83ec9f60ed8a4197a763519e20fafebd378513694b0fa3427f2e3337f5f3c1fdf7b270d68ac554b0b7ef" },
                { "de", "1f89b739c3252e1b733249ddd773ec91ed17c5f35573b68cb62ccaa4982e1c1e2cd17e25245649c2ceb63a2675ebdee17518e3f2d3f1db4535dd42b065d2f058" },
                { "dsb", "38aa4e8da7970544c22e4ab0be05600416cec100f241567f49509caf6e2d6bb365c5c735c2ae02d47731fd96b640910c58bd8aa94859b5929cb7c36af2363396" },
                { "el", "b9fd1091fe1cd9a541efc90f5ce51174dab235be5c7884c24b5d9f48199b1cf6d81ecbc1aa05580c7a9de3dcb3fb542e89bc956ceb60214c3ab7e9a51ff74ce5" },
                { "en-CA", "b8f2d908270e95239ef81cdd672b2bf179a4e421534a84421a4ec478fdc3d4c56be6e1651a1337745cca4a07b9b204812bbf40e1269a7a27a8b90ccab2097a7a" },
                { "en-GB", "c0712308695604948a091447fde39a91dc976be63c3a11af3a2c82a3603453ea95bbd7db150e22c0bb329db551fba2877e1f1d7d6cb3a57f4dbe4ee7da8af3ff" },
                { "en-US", "6841d9958e2551311dc75ecdd71ba412590c01538b7c67ede4a6a161ac00fcc9875645d8ff45f97a4fe80e0063bfd26112df646e9cff70b11396e1ed097f8d28" },
                { "eo", "19c4dc342e3c1dfc694752264e20c87e1bedffd69f9e22be87c483f21e5ba457dabc1a615434ae826c66f5e1c8f0053c31b79ea7385dee612056ae8637ca4954" },
                { "es-AR", "9a7b57f0b37d2db342aeeac2361c8450d0800408473ebf4ae2d96327126b0a9d957972fe68c032328f6df25a8f51915bca3a54f183033ceb33633777b5671aa0" },
                { "es-CL", "9900afb379dbc083b8596fa415a45cea207bde38f4b7fac5d2d05035d145da3627db3c2132a9ade67769a6bf77126e5ce4beec89175f6e9e4d5bcc0f3cb6eec0" },
                { "es-ES", "8f4421f898df0c5db515481d10507e16b563bc1e26e6ba92d054f7e7bc1d632d284bfccf0fe3dc8dd9879327da697a8fe9872ed17f2ffa88ff6fd7ccfa6422b9" },
                { "es-MX", "a84d88b550c275bf31eec0d4c339e51c3c213b3dcca8fd5e3c5066eb624cb213dc00944becf5001fb8605b122b14ac2cfa7e85e749cb3c22550e76f99f054f6f" },
                { "et", "5f1528b127ed4e1247df911dbfdf732117a6891dc7e7da5310ecb33fc3141cdb94204df1008dcf1badffc6e68e656551745cc032f3e2c4c0dfd33e4fafb9c0c5" },
                { "eu", "eb48c8e56637b50eb0cf24d964a3c4ae75cfa1954bf4ae32be3116ed623063399ac0af34ed6d62b8bf6c5e9a1363a23cb7ab88ea837ade00e1f461975048f919" },
                { "fa", "7dba17e8eb7eed526071c6b5ac1d5f4c4dcdd8de76d076d840a17558d83109030807e8ed89462775b2b30a0ed8596b0be69fc59078af1e287741c2d1a4b1746b" },
                { "ff", "fd96b7ffd384aa55db4823bb3c5bdd174d1b4d59ae29b5a74a7c82b21356aaf646457a3d753c0c1788b248fcb013ec4562d0bc1794274ede5da85bbacbc5fa4e" },
                { "fi", "91534ba5f793a933a153cb573769caf8d54ce481c8acfb5d6028c5f217f74417d726e52bfee7a350992171fa14173300714a1a0cd47adceaae27f62aaa5d2c05" },
                { "fr", "ddc70d775901cc8ea611bdcd09a2d04ae165de33d0194c2d180ec7afe9166f03f1ff41bf0f2315abb826855bce2b38ae53074964587c135a8b973ee3bec9b096" },
                { "fur", "6ec624ea96ca80f81b216fc8c945725e2d35b26dc55450da637f83dc374ad6e0c5a719e1e57c228ba490a36bea964fac164a257a9092eca242c89cadd725e2e7" },
                { "fy-NL", "c2d3320168358098056217e941bb5d1e598b6fa4f0a800815cad166c9b03d8961d333ac2ae71131bc4e6cd5a841000e2eba6bf9672d5be26c8c186ad50444be4" },
                { "ga-IE", "9cef0af3fab7f2f39be197bd97a5ede33ec7a7a81dd42bb6409efce827b45403f7a4c98cdf03b1c53cb294f9abe1b2eb591cfb4182361a1079b0d237a77df994" },
                { "gd", "7dd2a777beeef1c28629c8be4c5fd2aa40ad856e8ec6c446e2605ac11780adceaa7517da481a0be5b6ca6ce85f4aa6da587646b42f929dc4b0d1fa13195b9767" },
                { "gl", "a05413d428f134b13e6256bc397e589b0ce93ec8760b55a30003e1c61d74bb71ca30ad06afcd8d9efa06719f974e2355eb42b2a4a9e0eb0965bf543aeb1e9009" },
                { "gn", "a0347cabd099393d2ff2f571d67ef50cb02812bd507269a3f51916793fd68eedbf97685b7a80806d987e1c3695ef6cebb060a187ea694c2b12eedb064d2ee341" },
                { "gu-IN", "e5bc6ef3074fb04793b5201da508bd740cfd4b70a851df60f369328917a193dbc903cfa6d9240e4de4a998d1514ad0a80f2ad0e11bac758140f9d59823e06e34" },
                { "he", "ee491cff5769400efc3d439632f7948cc6353b7462024320cd3d43342315d973b7f72fa78d465499533ca14218210b407910daf868f564a483fd2cb4353f9f8a" },
                { "hi-IN", "1c30f8b4de366aeac0033a96478ec5dcf3823ee0c278b284632c73d044a15a67ddae5873880ba9127d398bf8a1ebeca9e3ed1bed1f182b9ab8eea7c84d313931" },
                { "hr", "e801d92177d5f38fc8bb3d8fd8bb76bd4d25090a34e69f88469258a6ba8906566662e8e9cecacf788e6e76747f274dfe85731d9d4f3864e3c53dc7eec0daf573" },
                { "hsb", "d76f189400745b7cdabaac2615330274a726a430991825c2908ac73b6e417fa303b299980c8e21f81e3e8dd8197b29b232b96b05b9cc0fba0d392f67ce9fbbb2" },
                { "hu", "0a8b021691289c7cba5e48664841e17410fc7276c631b69813bea1d6eb461f10c661fba6e358e242c7cd5bd12fe6b66cb57e46bccc9ace544ec1b4194855df20" },
                { "hy-AM", "fe77c22a047a9a61fd6e524e155bd684c9fd3f95a8cede11d82300ae882c139d77302cbe39d0478165cabe3728acc5676227d794b2a0464818e435ae4162aac4" },
                { "ia", "37ffc06dcfdb1612b4f650745cae65a580216b8f275abe31eaecca5cd7a98f29ad78199d9913c5aee09f8680c8ef202c02886b9731e2633341173e2904c2e341" },
                { "id", "438fbc4e68dc8d2c5e39a553644e198ee4ff972a9dd8d801b4e91ef0f5bcf07c6877333df2e937e16d0af7c3918f8eb6ae56022372ab2443e68c85bbbc44cb91" },
                { "is", "e93d1777241555968f596999de8c2e523c23fa527477628bf577fae4eb34edc3bbcb42b6da3c689ad2ade89a9076f3cb01dd233601a34cc2525c6e28afe47f17" },
                { "it", "e24a0e3b055834e4f1521566303bfff26604d28bebc02bcde174280646b6dc88605390088d9e8b74db988657357467626857c1c562f60668087e3bb1065339d2" },
                { "ja", "404974b17b2277b3a4ac0dd0cabf45e9c4d68c149a6d85a4c12432585ecdec5f7104c4ff161708cbf1ca6c4506c2f9b627a84a2849ebafc9e6f7dbaa3193d840" },
                { "ka", "cdbdb159abbd8e21718eb69ab76833ce1a518010fdf782a9bd2dedf4868492a578291391fb3b9ff16370cb57d6fe01dc2ecaa8c82d454abb73cbe181b95c5b2a" },
                { "kab", "08dbf3bed0c7f76e20b3f5bf5358d6f908de0059af31dfb574989f7ba4ed6cea97a28e6674089cbe7729dc1cf0dcbb0308eef02bb7abdb7d70493386d9847cc9" },
                { "kk", "153f56bc26d56390138a753caaf6d2f1ce1aebf2da933dbedd6c2462f160d00fbbe67861862640a05befb38429e7bcc15bdc6efe0e30af1ca32107a48f4e5b16" },
                { "km", "9cec63de1a39911d6a7af4db5a2905ca6ae8cb7f9ec9c464091f7be55fc54cb34321199435f3776f575925c4b1bb7b8466665e7323fe79d48013dafa7898e9f7" },
                { "kn", "5da4910814b293856719c1bbf8ea65024f2f600724f03544283bbcbdacbea11fa8a154eb2511e4cf15ad05344e5147198606535f6f8982dbda2fb29dd967ded4" },
                { "ko", "49679aafecc18ac188488bae39f78cd068d21b258d02308a82239cceb782a36f9a04d50489168ddd858c110aac49aab25f6aa833c1dd908ec4434f758ad0981c" },
                { "lij", "a7fc1d28209e813a4803e7ba3f4f4bd217dc0b303bddafcf03c830e4fc7d0ed3f7ebc9597044aa5989592ef12e0bf2bf81613db2629fbda074da5420e0b06d21" },
                { "lt", "2168b3a84458279073a3a99322877e8012b0e7a9c3d8b108979990ec813fa1f44adea9d8482a5ea178b161f3acba77045ad3bab93b8dad060750398dfa26f432" },
                { "lv", "a887bdf002e2fdd2377fb082d28fa24ec876079c3ee5579151fe9219b0390fed7ff9881f4c226303b94a58ce6e0b76e5b0a3080d25887a8d5c0d0c9b6675ffcb" },
                { "mk", "002e8dd95b92199f644106150e844afbfc748525355b4b9da81461ed624fd40dc57ae22b2018a8af067929ef4ef61f5ee192b6f2de08f233871a92f37105ce44" },
                { "mr", "d4c9cd32100e97b5d345ac6559ce265d9de986f13ff9fb72246bfd195eca622b84ac593bd0d49d5ddc03c357eebd37758c845b27ae0c43e2dced71454ff70297" },
                { "ms", "056c3da4ff213b4617c6dec57927ca52656b178dd76391240ed4ce6d4029a367f17aa2c491ce0eae73bbcd2c83a908051b7cfe9727597c636b14b0027329910c" },
                { "my", "09e452dc7110e2e0e4690091d7e8b3e3d1082528ebefcbe999cb9646cdb1250e350df598596cd63467e916955e16e34594c25dfc4e69747400179c84841889a5" },
                { "nb-NO", "04d66b1bc988666ce2d21e60fa55dff8ee0604b59745f1c185699e6240de938400567248a99070f4bc98abc96c5a8e36e9cca3b51d7ef55215c42bc9e4a35541" },
                { "ne-NP", "9d43f903a23541744707811051ff7708bb917ed2f62a2e73300a215d6eed2e749e68d12e9c40c5d88e406f9b3f98b2e30ec234a36112d61b3e85a6b98f468785" },
                { "nl", "0af31275843de2635b8ab3144cdf3fe8da302b8f284377fb6d9256fe8aaaa62992f6b0e457856ca7a549e417a60266279bbf6685601c22a0240043e45d3c5173" },
                { "nn-NO", "f9397b617821b506768d580eddf0e9bc22b24c67cdbc8152125e51fa641eedf15f697ed7a42fab9c0c10ab40bcfe2195c5c9d21e75ae9555f2c4b09b52f5f8b0" },
                { "oc", "48e385ec01cce69c0ae8355ff0db46580da7a5c4eaacb2ad947bae59d2b3720895b2d8ee007cc8b08b40cf1cae5ecec044645b85f73e309856d0f3618f1c6ad4" },
                { "pa-IN", "e7087c45483f570ca42cafc2c54b4befbd6c50850d23d3c1706dd2f6ffdcb560fd8ff8e1c51fcb91ef3217f55cf8807dd17beef99d4a90a41f956bb81d2ac8d7" },
                { "pl", "f5106ee1f61b44c42291520984c43d7e582b4b8fa0a50ff976dee155081e821204f7250adf0700201b90172a4d6ec76603fa23e3e29a400ca25278d238d2d7dc" },
                { "pt-BR", "232e836e75947ac0ef49973b8141739c6ba7ca086f132989d27fd25687ab81698e3ef6ff1e49394315221d229e3c63554fdcd2545dbaafd9f9f98cda5c9d478d" },
                { "pt-PT", "99d34d71183b6e4d4e30f3f2f525e59d365ed47c3abc06d37dac9bb715ed7a19391bc2d92838a22807687d95bca6fda331f583dea8241fa9a40fd464ae9ffcce" },
                { "rm", "c23e28711d660ce1ac11268c1537e9cfb9f0bdfe7c1935e9e73d49d95b58076fa6b67af47e0999106ff7a0676fc8c221242d245d0eb9f82f47abc225b6cf7ddc" },
                { "ro", "f8319b30482cff50e5107bb2419ad873355ff1358607be020a9d3617bac08d1a12e0d5ed14b62ad91c31f0fc385563ed994dfd764f62ae31573074038ddaeb80" },
                { "ru", "ede461df3bd78a6e413e00a6c49ad3eedb750c1be9a657907d2ced24f6cdf7d3df14e434b97319f5186b329c59b7a3134394cdf8d7c95d012801edfa7f8b4467" },
                { "sat", "7187cae5ad761f83f8ac800d9312396e2e05a5aa6d921aeea3f4f08485e01269445bdf9a9596cb80ca634ca76abd5a83d1990b11c6afb5ee62233d09a1aae3d9" },
                { "sc", "f7dbd10f4dc46e23c06d2c082359f464a324af5c9eb78b116d31b217943add70229437dab7d9bf15f54897bd52a034815a9e196d6eabafa1cccae2313bf507c2" },
                { "sco", "673dec7a71ed42f7376975f41913e262f291f9889a9ac3914bbc6d98006c9dac4dd16190702232180fb2ef46ca4fa8567c217d5bd7d6b286cff294f416139c28" },
                { "si", "5c24da69214fda899f6f392cd58b6b5ff85d44692ef7c8776e7b57242ea0c7d3e8832ca5f12a9a55d9ac5060b324210d5d77d6123e45d91834fba2e6f455136e" },
                { "sk", "f9a5fa96afedce93bf0795989bcb55a9d46c57e8089ca1fcc2e708d5b872b8e7ae1726532a6907b211399a299a3348e7a2b61b8b0b90df2b85e7a268b72a7acf" },
                { "skr", "cd8132d8b6ef65d162a6bc8ead891a3a15a18e8005242ef040c2b5bad8117f05d5b065254fdd93c8dc4c0f5d95f2edfe1959626b80f8d25a67b8b81d4d63e3b6" },
                { "sl", "75930837634bc6067431a7d4d6e17b74fdfb625425c313a3c2b3749fad4d98e1687ec435113e067a50364dcedf23aa0a54da8e03686d3a5875d3d468c4d04d5f" },
                { "son", "90fe9d404c8676ffdad69261f264a25b7a990576f3e20c04804cc2c08f4e841ec6ddc7033d0955de06c8526baa39b7c9b18b75e08ac04121e9a7670844510ca9" },
                { "sq", "f74af300c1efd725e82a6c66d23d699a80ebed8491b249482c1f3e9188ec7dc02c8441d20987c87331fe1b35f7c8aff01438997653dd6d672151e2ca8c2dd49a" },
                { "sr", "e5f4803e259d5f38348240fd9572cb377e30c1207e0766545b0aa94f921de329d222c87d79c0f1b48babbdeccd85a8231d27fac6e432744a1461022f059b0c0d" },
                { "sv-SE", "f4c613377b6528a00c40bd21e9f08c9283c5c4d3a68b1a268a2a838207cbfa2b4ed2d654ed0f3b37b423978c8b0a4469debad1c10dbae6424ea481438a0d8e87" },
                { "szl", "49cd353cc02b24a6466975517ca87c85aa7fac344dfc883da900b512138eab3c2f114e2cbbf1f19d33bec13ab5fdc45fe7d93a52db823bf93914e550dc066bc3" },
                { "ta", "8c1e50001a532ef75c3f8ab6fd7208235b052f32ad35e6c817a4c4db7c7242a045f4791e44da4de103b3128d4dfa7732b5a29850b44b01aedd4b1c2e85e754dd" },
                { "te", "68eae9cf6df2c1609ea8cf0aff7a62d23f2a41714b10ec75a36c4a3e7d3f1bb9daedf9e271f848536a9c52a94726e8c28a3ec0a16814a00cd5e9e17bf7832cef" },
                { "tg", "5cb808f1b826997ceb5fd666da97b63947ee171814b42b76572112b2b4d7f7a2f44e7a7b2030cbd34022e5d478423c9aa0ae35fef319fc28ac206c4aed78eb2b" },
                { "th", "d59fb62468165ce996d75df00301f6ab069f124b4b2a764c6e89f36613a8823034e57b6fcf9cccf114d398359d7dca28298261070ddd13ff579a65c9cd902d48" },
                { "tl", "aff0b537960db6148c865f67508bfd67af8b4e7faa0fc9b3a87316bbec1535f6d814489e81c4a0b65c0ccd1ff4b037da90ad8332df1b0391f71314f5d1b78740" },
                { "tr", "248a60b07df8122f1bf41bcbd5547563f2daf36c1dc44ab6b0d6895f26c5820ea3d7c581c284d78a550b017f2be06683bc1323f0b77b99a0e18d42e516ba6499" },
                { "trs", "2010e2ea6c20cc24f54a0bfa9b7f929f6312950db9196ae43b43e5e1fc13f8883ebec3e614869c46d7a6ede04078e5c9e484e852b72312e73f2e6ba80c80a4f5" },
                { "uk", "c197d7a7a27aa2b6761b7f9dddcba74532a7f80f0e39d5576f29a92efc70aac4515e16d6b90021d01277bcbe38cb949f77484b42ed85495be6c24136f1da1aa1" },
                { "ur", "2a154d938e9fe1061a1cbc060e5e39e0e75cffa7358b954ed8ec134ecc54f24ebf61fd21fbe09ca9b087031cf1ddf2f6d927c1f1a3db23b594c61a9d3c93a99c" },
                { "uz", "4ef5233101d7452471cf89491884c2e1e8274698f80649577ea3db1f36792385c64fd3c8231a290f1da33366b069ae027468354461e75b3da7a162f8e5a4eac3" },
                { "vi", "76b7a5341201702093427396291f4f370c6281fce72c1b5913df4545dac2f1872a785d31523a4a536e76fc6344d960aa9a51e0955c13d3c4c736cd41ff367cb3" },
                { "xh", "581de154052932cd8c998ba01dc71863ed5b0d197b5f6afe4f205f166bf452dabc0cfe3e6a2f9244afad749090dc3287bf7373d7f9a94a4fa5658feac827cfdf" },
                { "zh-CN", "30d152197a3de9084069fb8b7b207ea156a945d3ef6633c227cdff63a4fad53f9f8f5d8bea9fcdcd847daa6d43854874f4948121e36a3745ac8ad09e72f69d79" },
                { "zh-TW", "1c7421e06e994934930d4297b302b7fd0c006b3e7432da6aed79e2599cfdae22a2eed18b282c9992fe2ad407b36770991b49705a672ad82c7b2826594783fa64" }
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
            const string knownVersion = "139.0.1";
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
