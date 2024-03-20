/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "2c2b3c495ef27597118b9ba60ba190dc6f7dbcab6e40ee224280fbf1e3e658da0bb7fda887bb25b608c82c94f28e1f966d89725bed3847d3bd87e00abf6c136e" },
                { "af", "aae92162d371ebe2d9f4b7734aba2e1cd279056a1d95347836df359cd95e71fe6b8d9a3bc202a1d26b6789b7f3db3f4c8114219e4340342732fd115afb30ee32" },
                { "an", "9379e47af4ddacb13a0ceca5447255591eaa12bda69a72b3ec548d4363cc71c6fb24fed8d9813eefb67646a16258c877626c99e4f270d546c427384a523f3215" },
                { "ar", "db828d2d22afafdf0c18138c3b4241c511492be9db9a0aa077bf0ccdab21ce0213fc5443976ea042e71ad58ffb93b8c3c2c6a90acd606aa60a14b7361c2dfcb6" },
                { "ast", "3af9089c98497a4f3f6b454fdd5728a6c984d5f244081cf4148919b2b10636aa6f42257c766a21c7af8a64822f4d85604d06462a4a3416a544718bbd66bdbd82" },
                { "az", "a024f6a797a974ad920624d30b6ea6709f748488fee41cf8e9b4d75e2fcecde07010b80093dbce85ef38172f1c949cab53aa658b2d39c694b64cf90fef63a1bc" },
                { "be", "da70dece3567dcc9a3e9d26667a9d47063fbacbb097b1d43d25efcb6da7c33f80c80a097c97fc70aca444e7181858736a2f189558fce421a18fe66333959f357" },
                { "bg", "b8298857757ff9760d4227ae476d0785b564700299421da4603f09b28e76003b5448d85f9e341b5313c52b7b436c75dd931df0c609e5d830abc1f31569070fa2" },
                { "bn", "1c625a7f0b6424594bd0f5312d3cc5782d559ba2d7f37f9337aed601fd5b3abcc993cdd4b28dee33a6d4af526ed8d761a2187fddaa8d168d68e15ba44a61d347" },
                { "br", "82b64d1b719fe9d4ee6c40d998441622cd743d81400b522e4bfa0e47ab1fd6df5a17cfa627e414261d0a174547e922ebae02b0124570fe97f265351b8539eb9a" },
                { "bs", "9fb127910f11806cdb3dab4fb654548599a29053dbbd539d4877b3fc12564aa8aecfed9478e0cd460ddd4b31c95b55ba56f0dfa8cc578dae1017a91f29a805b6" },
                { "ca", "89950b5427370ce1f91e8b3e6ad998e0df660530e15ee508601b8ffaf84285778e84b914cee1b4b0676bd7d0443dcc73e834b8c9bd4b61dfa353fd8729c5fb7e" },
                { "cak", "636fc304284fb563d16ce5d1a575a3e7a51199ab87ee8bbfc5f0b3106c5fae2ec0b152428ad3f3f8a73229ad5aacaec1d0cb25bd67492210bf0e2a98befe6591" },
                { "cs", "c3b4d822a63364c609c6923294bc98a8b62e14946488701eff2702be01f694881ddfd745cb6531126b8b28b9e5f16a6a34f21a77176f38afba97f694d1f44258" },
                { "cy", "3551c4a9b6bca4299bd01e07ed80ddf6dc773897a19053f184828708cc6fcba05de5064775ac5800025b6da43abade72ae582b333023707d5e40c07235b5e6b2" },
                { "da", "492824646625bd79bf37fe7a0bba3eac681ed51fb019b0626456dae319bfb54fa726dcc8241889052b8901ae6dd9eb7ef816ede9c6ec5845641c13ec5941a2a3" },
                { "de", "ea24058367e329d8fb81eeed3fa8ea1a039bbcc2757f9931dca7d95dc3e4e57b0cdad0c75aa5a1adb775c68336fd19bf2bb38ca658339db426c970acbf73cd57" },
                { "dsb", "696090e9d459af9bfbb9095e648dd304d28b7df8fc4997e11e6d6150ee6b65bd9ff6dafa75724c9e5b1cbd3583d146becc524ba512506dcd3ca5232ea0f1f1f3" },
                { "el", "58eb8634527febf9aaa4b1d99f1d566bc88c67982f85e227f27033864fc021aad8eb04f5cd077b4b2e3716767b99d64b3016109f93ab359db83dca0ea9426870" },
                { "en-CA", "5aac49e5af6aed7eadb34641edd27ae071edefc80af80c4cfc251d1bf49bac2480d543d477e7aac9c38a165de161e04fca72d8d5f948c81b56c70f3a3b6d21f6" },
                { "en-GB", "a6e8441e5524cff66014e6db19bad2dd7361738521aa38007aaa2f74f6b860bf7882751dc921cbf403dd61bda4e1549a9db6964dcac7b24b2ce6a5ba4d4ddd22" },
                { "en-US", "14e71200a40219b5f67d6521c2e0f03733e1592f0702899cc52cada526719959a2a7f07d08345ed83b8dce8d4ccac53d77e35cf809575f6762b52f1626c7b1ed" },
                { "eo", "cb635d30292858ca534f7749dcbced856693f067cdffc646008018f5847cee4bf985af1754df4a063e27ed16cb5a46aaea2b221e745850a3819fa54d00139516" },
                { "es-AR", "53c5406a45a570e4961211549e114896e27401676f809a0218051d35950c9d16374118ea967f38dbaee470213de62c7b2f6211ce053eb243a89eb71b022b0761" },
                { "es-CL", "11d13847928aa3d769891a9f62a1b087596230c511ca5a30b8c9b6733f336dd5f2ee5b3500c1bcf9f106edf4f28a80e4a79a701135a57f95d9d842c8f663f2a7" },
                { "es-ES", "da9df6332da5afaf3ab7ffab3d3011251749ce4dbcfd9f496cf2d564c438f765b1273f0bcd3d5947815ba8e3e6e9110800f4dfdec1f94afd0c6383c4578f8d80" },
                { "es-MX", "db6f8fd3066d1e18a175b1ead5827e8de0a2515139bdb44b09896719b03ea0acb52fd2aaf01b3d86235af158e7591a846528663987b57e9412fe1d8a5f418904" },
                { "et", "6b9077ef26a29bf6761bd36e75f2738226d2bb95621d6462b056f78f3a6ab7ef1151c6201be387a0963f2913d10f100bc596f6b1d1580ca735c9a9d709c683bf" },
                { "eu", "7425270409eb75175dbe965718167a487d47480e0b3cb447b676cebc9ec9ff889c2d10ae6751af8307ae4786f90280130dbbe40d55c901c2e00949c1567c01fc" },
                { "fa", "9233ffff1421c85d637d6a973ee707fb826a7ccf7e27b8d54a9f8103175827b29ebab73f77020e7f4937e463f3c5d1ee38f0f36b52be1f943d8c40dfd0ff8c04" },
                { "ff", "c2d608108be6ec20b0ff1c6abd1340c18cca61eb2c993719a6d2d5efb8e6b6df410c52de37b080c42f76724d9d6e5ff10ddd5159aaaa5d0b2867f139df554575" },
                { "fi", "050210c894ac755651691dc154fa26b9fe80e852dd6aa60e26f5cdd735471752b0a160d1de2b30308ddc88a31ea2767c79de83ab2badcca1f08fab661a308756" },
                { "fr", "490050d5f930e185dd124e124c4574f9af10b6fbebbd70eab967173b0677c18b4f50c4f48d76211f0b8935fb87fa0bc6fa3254bcf3cb33f304fab8224ccc8337" },
                { "fur", "29da508cc404653611e71ec63e510e9537c68579cf7d2beb1758b1ce72e3fc83abfa2af60c0cbe580b030203406ed6932ad8b543b436aa15bad643d6cce5688c" },
                { "fy-NL", "b0609d818a946a96af6442023e1392cdea65c0941d89e37c08e67a64ea2c3a53c3a846f4c745c68639d7e8e8ebd1c388d8adedb8160e1df670204d9ee71c22ea" },
                { "ga-IE", "77d765fc6ffa01086d043d74499d4cc3e31b7dabb4039f3f08b44d461c3089e9e0b0373867d6037a894e8c1527f8db6b1e50c0c0a878f8e0003b800f4668851c" },
                { "gd", "e77b9ebdf6daa328152c9d3b0637be4324d4fef0a66d04518834ad0e0e2ed91e21fe7c06ff5160d6691dd771e5ad9f591dbbbbb589375901dfbc2dce19993a06" },
                { "gl", "9143e396f98c33e2c566aa2e8950618ecf42103813c0ccba7968893082826305254b5bd71043ec7a3831c94efb4067323f5b83794613617902a95d5b89a05081" },
                { "gn", "3ea73223e34b5635acd685f59c0267298e07e54f40268e171efd6f0a5012f2fc59cd0f0eff4fbc5099e291ea2bdf36d1798b00030c0609b84cac3e6148ee34fc" },
                { "gu-IN", "1389fc110cec749776c4b01c2ed3836575bb5901cb88b95dd62dd54cc4d9df761ae70c68b8d6bc95250455abc4ab0952976a18e76e09ad35a20e495089be80ed" },
                { "he", "ec2320f4fd1d636e7199386a3bd60559d8a478d9c6136acffc2f389c6bc2633a662bde12cb8a1c5728ea8d44176fa2238c24499ea81bc3e1bba383872a3868b9" },
                { "hi-IN", "06d5599025fdea274a3c7879320ebf645ef7fca76ef90cae80cef660afae4544670dcc31b3534ca65002a5fe07236c613c9da717c4224c4c5ffb42339f0d0c8f" },
                { "hr", "89a2fb2b79cddaf5d44514957020dcfbde3789058137b7ed5aadf0d92d42530671056d44764b88b526f1abab065ae665c9880df5d49e6c1ebe4656bad330734d" },
                { "hsb", "84495fe2f9b58dda4042beb15d9a65fd82e370506c8607d6fbe54b5bc16af625ed4321f1925ef9fa7d88a224b01899ec449d11c0262f9fd0fa2bd0b6976b951d" },
                { "hu", "a83b46162f416759db570b13cfd8145edaede63391491cc5c3e18cd7a918ce8623c0ab85a368e5815379bf7de750c7626d0441f6910fabcce28d5a7d5f5aa34d" },
                { "hy-AM", "14057dcb9c618ff711c1f66c0c96b5ca8978b96ed93781fa5492e3ba1e87522bc05b0bcbc36dd4e10403fa68ec4e8b18e89755d1e8982e8dc14baf1cf13fe43f" },
                { "ia", "6e1ea14c16cbf9d8fa902456baf3504eaf0af5a1618e95e34466d95922136282a4dd225bbc73e5bbec9a802dc5e075a6e8263e181da3794fc60a79e4b316b827" },
                { "id", "13428b11eead9e5c84fc0c6f66dd51b477dcc328d47bf3fe556a8448d9d45ba7558635e96e63da972684558c73349d84bb4fd2fe8e6e73f8fbdd4e0b5b82ff8f" },
                { "is", "0f1e565aec85716026756b98c6728526fe9a5fd0f758df89f38530c2b9bdff94a18dda9ba59075b90ac4720f0dd6787ea7702c7aab7ab9c4437eb9b982f6231f" },
                { "it", "f110f24fa75091bbdf25f83307c23fb2dadb11fe3354f1ee7ef4c50f554dd5852648f5db1fcfc654d24a828d546c43cd5858d4344d1070b329c8f137829baeba" },
                { "ja", "c51035df3842e9c45ba28f24ddd017d5a0482b185e40d0bbf34dc9540f5095d6e217e27c615c08f5f96b4b6a9df834a674158edea74ecf08c43780fe9f018846" },
                { "ka", "e5864ddc72e8ea22f7d6bdc33e1449bedd9c44175a4eeee771bed244a582902b953e1893d5fc4d6c28c7d6f20fab3e9cc117febb4a261465cecc7fa24777e911" },
                { "kab", "3dda665e4e0579b532c90cd21a453b02352af02862ffb9e6371c0ae749c9b11fa1f1ba56f264952f3f8215efcab2ed4e157d8ac61b03cf8e075baa684491b773" },
                { "kk", "71c2fdb8f2130d4fc5e1170ebcd7a7bee0bcdfcf7db18134e192d7f284524055b0aecdf78e58c207bf2e888456f67163411d4c18f95dd8c180c5391d325c0773" },
                { "km", "194f157e4d5c2793337a9d6bab454606eb21c4adb13f1bcf009812e4892644203b8e11c8a4df6ae5a34bf0a141469c4d33e3cc0822b13fc9b0aba36cb778c174" },
                { "kn", "b1738b1cd029fa0258b8473da1c37f0cf4a040f87ada9fce8ad7fde09f59e3c4d310f28d59aee8aa6e7920ea15b1849dc1a17917c2898a2436b8bc4f5c114fee" },
                { "ko", "a42984593f4a87b7b0b76f7638d6169f519ddbac96d541ba417156986a969dcee1f9be6e31ddbad2bca8292d4f9d72d16a6f6880ed47fdc7e6b4828f952a0d3d" },
                { "lij", "e3b2870dab0a6b80c2bbcbe81e516eccb4bd6a4d4b73c9e845945fb846219912f3bdcd849889e9b0172b10ffe089724ed6994e380e398775349d9368e8bf3f6f" },
                { "lt", "1f97d552c5bddffd002af103da6fbd16a69026e853173df309cd4ea7808458aad915060bb13a08db63824701e2b83966a96910efa0754d9b755b9efbafe71370" },
                { "lv", "9d925c7d2aafcda3ecbf195f96657366d67b1284ee250695686067dcb3d64022de4352ac8c5801a7dfe83e3c876e3c0e3db2e3427f529727acf3598718c54b8c" },
                { "mk", "97a4009feb09c191ee35155492e4b1eef8a4748515b230ed4aea097092bb43d76bf321f040d89413a06c990d3502f388df7294b8bfbbaf731da950b2b3f7d32e" },
                { "mr", "6577b7e27fb7493dc3d8975b4c7d80ea882543eec4e3879aadbcbf52bd7e8940e5277910c459e54152dc7e2034b4fbeac2a8625607a69c61812ba1ce331c08da" },
                { "ms", "94ed7d3785c710e077449c3b47b9b5d0c677e0161743aa46eb487cdaa15bf3db76ddd51642557980f22550d98b1855fe4fbc7768c67030feb02289442004684a" },
                { "my", "d666d49cea2ff756c02d8aa013dddb39dbe3cdff5fdef17f4119ce677f72f413d3669ee76caef9bbe84f04f75b357ff177de49c12c94a3dcb1d82107fdd69acd" },
                { "nb-NO", "e5799de055877eae2568a042fcc30ebecc853574f3e1641705c103fb3e5262d69c938e9298330e0c4ae1219d18f3ad34704b3c9daea41fafae2592e45141515e" },
                { "ne-NP", "0ec977617aa4afa6b9beacbd5f527dc1c59007569459f03e802639dfe00bae040d7a4cec991e15c9caf4e31e2cc6ee6bee8d12a09b113657c75f3479b56e22a6" },
                { "nl", "6981a38599ae7396b924670e1887eb3e93b09f65ad24cee50dc238f9b3c4fd139762a58199e5938f7350d2f2c10ab727c73d64bcdad3cde8333b43004eb552d7" },
                { "nn-NO", "652f6bdbf0fac0c0f8fa5646266a906058f712b7926c1314477ce097cae9ff9fe4e24e2e80ff6e10f5949e0213a50cb60bdec93daba91e3f7062336aa6561d4b" },
                { "oc", "e255d16c4e7374f98e6c16151faf744ad919c7d5bbf3c8468911228c429f9077e6360ade34aff3ffb56f492772f23fb15f5e452aea384a8cf41611f441525878" },
                { "pa-IN", "6cacb6d9ec5f655fc6b85a4548a22aaa6891c46a78a136801ca855c29263d06e3aede473dd7ed9f6183f29be7c8b4acd26be47f8be9eac5d87bf54cf7d287d39" },
                { "pl", "d24598f17f79a8dfe6e5e78dc8f5a876d2d9ce6706f32fbd3de65d0ef00e743db05d688dc3735536217dcce28e230e78f14f6591e24565af22694b952690c9c6" },
                { "pt-BR", "6a1a9ccfb93a02d259cf589b780d4aad60f3b8f2b922ad7caff83b63c4f65862c889a76106a1e5443e1fcec11e43b55b755d3475f8d1c2184d5dddb0c6e99415" },
                { "pt-PT", "2c0d184e8f58784fc58b1bd07861e32acb676eac282dde02bfc582c56e1dde063f9fc7d901ed585e49c20d2f3650f4617caf19ec7efc642f8156da8b60d73e76" },
                { "rm", "f6ed5bccf588f0709305b994c4f676b00b17717972d65fefbadb1dfc37a9e87d8cb91ef1f82c7c1bf0fcde173ecf6f4c5db5d4410a81daddcb96e7fdb77ee959" },
                { "ro", "6956d013b7e61eb8569659806dfcf90209218e73360509f1cdc2fd030b78b48a5859854308f94e3fdf551cb9b63532e887451f70933bcb44fe7c9001852e05a6" },
                { "ru", "90fd7df9048fea13891fb4767e9c25ef8dd0a81af8461704830db3d47d680e73eb7b1ef977119f8d845e20800b9f2e698d9309d61122a4be89b256d07f96d9a3" },
                { "sc", "022166674afe845c1199f72e35cc451eadfe3e1489cd4e10a90a4d694c1fecd391dd81c5c3665c88c7aa3acb1846ed2e8893adbeef3e276fc57b2d14d9907928" },
                { "sco", "aca346ade2ee331cf643984ec979c825b3561de475312c2fcc9906ec5dc407656ca4cc8d067028ec22125eb97a460a02b9b2b6b18377278f26330fc591491706" },
                { "si", "4580cf397b31b53e80bfd07730964cecbecdfb0e13be8e271065a18eca5a4e0082f4c59dd931e13603691f5acf8330b30a80959897da746979622dfcf0b80e14" },
                { "sk", "0124b55321653c2e4d18d5d410b5feec16307edcd03386fc372a542c672c7db54b83dc9513d04008332e458d1704ed8012f242bc62f6edfca7a412ca05a036ec" },
                { "sl", "d1b5ec4678c8d1cdc65a6235ea9b1879c2dd9d9227e71e1058511c34b4208d6923997d396de405988d75be48d302bece7147958a241edcbd726f61936d491993" },
                { "son", "b92bd664657e7c18fe3b0b79d8e1a2c1c94d70104a8950b3548c49d5159ef72de6d05e88a23a02475016fc7196811b80526700541d58f04da8b196c6ec9e2adb" },
                { "sq", "5bc4efe6459363682f7ca12390198704f369340d6852b1887664679746a2c6780a0c9a3a7744b2096b1c680b00698f2ccb93e684170044d35b751dbb16d65f37" },
                { "sr", "d3872c1fd2d13fd7bf9e09dbbd67be7b2036adc065402269adedfbc60726a8e31f0189849a2bbbf81c8a77e679d8935886929ce0a99b1f0c613a31c59ceb2018" },
                { "sv-SE", "e445c23ec5fb26f86264e8bf1dde8ff9fe684d12fa0f902e3ca18183aa3131957271d0a379d126d8cefa0bfb7549147dd2ef94e8c234aacb2b681de8c4edb56a" },
                { "szl", "237d66b69df447afcbaaf7a3ff56f60b85a9b8e7f12efeaa281ab4cce87edc92da837891e45b54d69b367647a804d017ff6751a96eb81e8d6a5753761b8c8a55" },
                { "ta", "3d5c6d3dc02cc4db431cdc4264bc6600de9b6d4cd666003e37f8379c26977587ef4d6963ccb292f6f695ff3ddd3d6786139fba097fca91e701b72bf12ee78878" },
                { "te", "101bbdfe58b78bf3ab2a946a9b553fdfc4cf386dfa01f1ab876deff42acb94c754b5dc510674ec4e55cad25ab630b0eda0473a2095cb5c85f005b3302af42b15" },
                { "tg", "bb8879dff82f302eb9f09be77f0120058780eea44d8fa4a035cf9d30ee96c0be3b402aed4b694d1cc2cc574e54139ca02c2ec3f36e833808918fbe6a644738cc" },
                { "th", "b575d7704fd18954d82cb231b96040d655048a2365a62af47ee08d4017f2b47a21c4a99bdf4be59ff7c11ea9af4207a0479f36f119a0dbd2d1edd11e8bf0e022" },
                { "tl", "9c728912477eb8297bbea0f51450897baac460bbb155267ca75987d9dd5705d28d9f11cf38f4b14ed76ff427c71fac11371ab177abf18fd828892a814dcc2e0f" },
                { "tr", "beadbd7b2c02beff2f93a436056b7a39ebb5a055412e737fe5a7e93aee17071f6a67614dc4226832982f4fd9e9534fe8424b7e3b38c5bc7d66b8e4895718758e" },
                { "trs", "7f8f9fb68ebe8129140bac3299d6cd2ff944dd56e2dc4abd5ee684b767e001afd3f7e0880bceda5127abf03c32ecfca7ca2cbc29d7a1ea479c8641eda3fa1b3a" },
                { "uk", "c92073cfa3c12940309a2d2ad179399ba95087a69d25fef1a2ede9f638ec569ff9d4cb843f5160b7fd9008c3fe9833bffd8c55801b62efa9cd8d02dbfab737da" },
                { "ur", "067644bfb5016d69ae33cf6e6d0c28c8277793b995ad3df05023f899dcb2f468b25af22f4196532634356af5952725a10780798b75020b3c89a1f71c8f096b82" },
                { "uz", "2182e65d1f5328d66b67e42e155765a45fab62928acdff028c915ce0c8b57fd91bea5dd4be77b4bf0bca0f86c1eb749738030b87f241e213755db05863d4a82b" },
                { "vi", "dc19ef19091e0cf43818366a6b4cedb2bd9ecf8956303fda31b9bde63b653a2511abb3e572a0bf0f037173e0e304eff312b80a9b3ceade947abd58a343dff06c" },
                { "xh", "b1b1b47b30afe85a30046896096d9488f82e92b97396252ad23929290e8c966c124ed99593cab963501637b6ec56ed96843acc5da8a6e27abe6ae1c54e62b953" },
                { "zh-CN", "c3be0fd1aec27df05e07a1501986d3ac925b1fc721d1d56395f62be6e8112d50c3b155e4385ad677238862c740b186f92f8a6c11148c7523dffb073ea724b7e0" },
                { "zh-TW", "18bb58bbc8f6dd3460d3c60076ae2f59c7b4d576f9f4863a1a6a29ce05ff4e244f5fd2884eb7ce1c8b9bddf6e28b6f6e9471fb55bda29b3d266bf5cb386db162" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "303a2b7578b5450dc80bcf11217167a5205e705f954282e48f746bef786753ab332b337798bb7a3856d205dd6833102da46508ab6bd505e98f42e7d8584d3f14" },
                { "af", "d41c06fcb77cd0508d701af12beb3ce5c36a49d855980e780d8ead496f2e84e9501aa6055a8f4ea2aab9f5d9702496537f9509e373602e89d655ff057dcf5379" },
                { "an", "be49698500dc88512d5d3ca470333b41db1cb1f2fa8ec35be51abc9ca0bae1e219875ef6fb2e5cd5f92d4534a6fe7981b6b0a47ebb451952fdf5cc57679c083a" },
                { "ar", "236580088fd93cad5596446a4497abb4ff4b18ef6bf0239d96155a829cf1147e0f69e8359a8356a021b323053650c18fdba87899e48496f28890fc54bef9feb8" },
                { "ast", "072d1b3ca5e7e5a6e16e1167096c5c863a66ecfffae2201c16c8b5325b761524da783711c9252d6aa8827c51ee8c8e5c4b1221d5e9ce5549dde22b6ab0d6c1f3" },
                { "az", "9486158a5652e8ea8160884350b6eb80c325e89f7040b06322e004a82cf124480cb8389c6c8cc9fbd2d842496f9c40c1c767c4ef82b7afef4ea0cdebc8e9bd65" },
                { "be", "5cbe303f530463643d9d41d934a5a50626ed36e771a1d68fc442294bf8d4139d803ce45b209e20bbcb6b97fd5df4de0e644b261ca7d4fcd62b2088f9d7d6e837" },
                { "bg", "8a9b9e2ff6c2f2bbfbc01d34d9264e6887a991e8d1d27218043c529cf643db05685957440fbac6420293a4fc7fa7527e9cdd7a93f938e77876b7c240f1f0a194" },
                { "bn", "9edea63b7e4719120720ca26139d2b2c02aa771ed252ac66311d2bb7b1f223f70f3de2f8d455ffcede0c9d9c4a43f90b305dfbf424b68478617285ee1c78133b" },
                { "br", "1e4a92c834585ee21c286fdcd3ff10337410ee2a744fe26e5cc5d3be24406d48a2f27b029d72de36ccc87fa4afd2edcba3df732b2544c214e456915796917a8f" },
                { "bs", "c1d1581ab4a11c52646e500139839cc1ebab0ecbf326798245d5c7d2dae0c36fbebb9536a5bae3df947cb8e0c3151174988364cf13d78eb7805e4f42bbd93141" },
                { "ca", "cf01507335649fe71a702ce52f4ce937f37b349c96c1fe39e40c04bc7cfcdaa9f978ee20672eb5b19ceaf6ec91aeac023af8ccdb9fe0e26a94cc6b48b4efa1e3" },
                { "cak", "73a2110a868f0b45b54f40718dfafcd00134ad330fc75fa775ac3ff59e50e6bff4eccf6ad993bc3a108f74fe0baba878db37f4b542191853adebe81c06a24d0f" },
                { "cs", "39064066b8239b0c7efdf119eb397852dc73bc02da5c1698863164d206c4ebaa2cb3c06a16608e6cfc1bbd91646b6d3ac67cc1fa52057f8d602d42a5ceb40074" },
                { "cy", "fd2ceaa370063c67d6e337d1e8045d3b44883c7519f15b006672a9a1c2b3914336bdfd91c909ce72f73b87990e1710c454c83ac0b0f30061066d291648b98e5e" },
                { "da", "d01fedf655a8e300ab47f248596aca297ebe70c53efa313e52562ccc92c556bc1c7f62380bd7e94c9a3110ec538d58a18eef1e3605cbc4e7a7500edc2fad09e1" },
                { "de", "ec5d229565fe285bc9bd2a30e8fd3e04bb3b11e83115dfcd5c3430420fa22f39d809bfb790b09df1f3c21fe0c59b196ba095d6d3d4aa90025c2066f2694176a1" },
                { "dsb", "4727cf6d0b96cd71d16f9ce09b18372a8cdb21b2056e2df289455f27d14efe67b47e5bac953594a8cb1fe84d7240b490ab71c22e0ff8562e3c6ab31c303ee674" },
                { "el", "32127027528223b34e3ed39710d06416f31343caa8db33d6413780f84478e4d2499c19b3176421542d4fdd29fc1a3201dfad49f14b20f88d6b15af62598b01a4" },
                { "en-CA", "82043a39fe8f87c1e3aa0f194b92debdf69ee31ff19d74db4ab5911c6e01a643f9626561ae69146f1d8c0e69571a00c95a0c11186eeec5e26fa3601017e20b1c" },
                { "en-GB", "d9de6e79dc558acfd8c357330c14f89b4ebe18d3e11fe90021fcd1d7f0bdf09a09918c6502859746b540704144410682f9d94dee92b1e83a130296a74a20688f" },
                { "en-US", "e5d473fbfdecb44e7444ea1a9579f53bc6eb52ba43cc0d664a7c54b6edf99cb0b51de0a035c6fcdd85293c7abfc52a2547ddf8fcda531ccd303cfa7ffdf565fa" },
                { "eo", "5579ae679b8b0c4e60a786f4e4ef433f28e998c196e728c8755bb8992a6248243f22fff6b7103be8eea3566e575d4fc9f35c3821265d01348d835d49b7c003c9" },
                { "es-AR", "57d8db1074d3ab23e2e7293029360093306d28f2f4ca4a1bd829063977f8afe428d868349bd57909f2eb552c36320fbe774b00d86af8d5e114d6fc06704b166f" },
                { "es-CL", "f56152d94eaeb2c48607e3a2895ceea5afe0611e70a32e685ce2c26bd97d4d500356533d7a9f26db29b69ac282d2b2915497a75a60bfe1ef6f211d615dcef32c" },
                { "es-ES", "c04c2e61fae75f3f3ecfb84ca0db1658135165c74c6038b65c32caffe64b5181044733dbfe75aecba1ee56d335f5ad5cee6dcc3ac438bd45e3a7d4b1fd1e9a40" },
                { "es-MX", "1b304910b6d5c2708d08de25807337f5b420c8aa1e22b0ef72334b515020ffc3a7b33b307f950d0637ecc63b7fe6e8e3bc8c919719d312916e36530a74ceb7a4" },
                { "et", "0c4bb0b223537d843aba1306caa3541f25d80fde6425b5ad024c221bdcf0371fd4ceeaff6ee1bcb1e6e8275f6b2aadd9f495226a971728f979610345298c46b3" },
                { "eu", "273e0f3e4e735f7332dd4b5e307ab231bb28d0e6ff6e59edb64030386d7c8f19c026cf08122d4bf45a813a32dd4e9c9a37b6ca687f09e825c1b0b4505b30b370" },
                { "fa", "d5045ccb612c5648b68d2eb57fc62f1fb9ed768b4c434769143d659c2b9c7135b9cc175c4b1cc2ce72cf043f3e37791d9b63d20376bd214080c5b1812dd26953" },
                { "ff", "dcbc2494a91dfd597dd7d836bddf872855cbccd2d4e97ec7ba7b0b9caee0f5bb73f4c7b13ac285f35f39599b663631fcc2be482d6388123de78b7f347ee4951f" },
                { "fi", "c423af9d305c85c059ddb00bfb57e1c9409118e27e8a4de6b1dd67d176ea7a8a1b43868bab314adf281caac32f2877660cd39272ff28ff13734324d758415b9c" },
                { "fr", "d92e084881f1117c2b6846fdf069cf00b520544176fef13e1b74dd94b5570ded3da0bd2eb930da831e59eea0bd3e85de7bd0c7f17e5cef03b461a093bfdc8d37" },
                { "fur", "01139bfac36be2b8647e9c3ab4fe448ae31a84bd54aa2a0ebc283a54583156cd491f1a0309ef701db5c90e467493ec9474460d75583e47a9258f1bc34e5ceefe" },
                { "fy-NL", "60e9da45d0ff034adb71cf9d601e7d2190d6e6d9aa5ca02564dd5a4567a5a3b36750d9c756f6cf5628921ce39f3b0d16081cec72758d29cf95492acd637080e5" },
                { "ga-IE", "c807da3241f8db5f46e5d5578aab07ca18d315a3c832e4dfcde0adb0b8f46fca15f8a413144ba63b5df337b51897d3992f2d08deefbcdaa0b95a4e59daa0a240" },
                { "gd", "4e38d3b8c0e5fa87cc1a0d99c45a286534c3ff9ad511bc7e639b78968a58870ee81846cd79ae26d7aa10159142affa7308a6a1d8ec8c0023f62aabfc4eb00acb" },
                { "gl", "709dcd81e2d4250fa3fd19cee92dd2705392f91c20c5eaf293a3fcbde9485085bc1f25e7395a7a3f0adef6e9fc027d5731aea10d3f06ff5d1c64ae9c6d5e7769" },
                { "gn", "1b5954402400b89e883eb0ebe5a973bd84d060c2067e098358cbfe479104033c89af601db26141619951adde0a398995695caecef669bde5c4afd69c30a5364d" },
                { "gu-IN", "f12bc903157a4b120fffa924abcdb283fa074fe88c6a87b1ba05e196f9f37e9a8342224947f2db23e35486418d3a2a2f5195dc89fc4f661d3870c4a41d2e99dd" },
                { "he", "775d72354aedfdd3df5380a1c30ffc1328140dab8caec475cb57539284d7ffb2fc9466311a41d5a3bc70095cfce8d339dd440fb103d52069f321ebdca26eb6c1" },
                { "hi-IN", "250600d010255dac6cae449e904aab20b4f0bddaa2f749392742072a9bf5bc42a3bef155b9c29232d085c5f7664d7ddbc194fe65c5d38ca619cde58c674ff3c3" },
                { "hr", "51ad96039d9dcccd0102f903178ecf1c723f37af900c1c7511a2b16e67c6fa58348da727f0eaf2af646512ba3dc6e77daf5a9abc5f0981b4625334a500ed5ade" },
                { "hsb", "7a7faf8e20435a1ff0c976894a0e1629c62e58341e7db60fa1d2fc9faaa8896d6e9f33fe6f37544550a9c89f7bf163bfc4668c69867a96ad4a90a207f0fd2372" },
                { "hu", "e4d9ecd4439068d933b6bd11a059b447500e1af75e39796752571abbeb67bc7f69a2386fd1cb172e4e366058ad1dc8031c9fa2a1057fbfb46d9fc9de348e24a9" },
                { "hy-AM", "12c8b1bd240287f7c0a61132efd08342df120ce5dcecf334bf28847135a7be1bb8f6a75175266523596dd37ba1b993c203e57fb6264af8f4e4efe3c7726b857c" },
                { "ia", "2efa26d44e8c0b4f470054ec9052bba67683f21dacaae888317d432a9eaaf2aa8cf6a4590d2007ed4f34668c12ff61d8b33b7b4a3c0e5af033752e5798f4eb91" },
                { "id", "240487429d0555d348d76ac59cabf8eaec2c471f203a7af8086aca26a246182b3e294af056d18ac24596bf42c561cbd79d040d82cd465b5fd69a13c0107cbb4c" },
                { "is", "8b183e953220dfe52ddb01b24a152853bdf047c047f18d6e0b9d6eba53b7d6a197d54498dd2d9bcf2146e82082208460a0dbed16fae19799414faffc92dc80d1" },
                { "it", "abe199249c671decf0ccd3980c2459a86741f963d9983ead69790e64c3ea664ba1e1330f97c774f592a0a4037da29e214aa05ff829742c5e089880222d8db72d" },
                { "ja", "401c433d5c78e3e697072b08033f1252324c59f3f5c404bdbbdf31843bd0d34884ca0bd8ce8f9f8e64708a54c606bb3ab9999f92ef2adca736294e5a1833993a" },
                { "ka", "2d15b844f2b767ce99057dd054020eb80a0704e32740baf2199a6be37cdc965540072800ba6e781bc727972f506c6b07107adad272cc92fb4e02c794bfd0579b" },
                { "kab", "4827a1bf8dbfd5649daef8815221dfa32d334888a34c4933cd1db5a2bdfe46f90538365cb9e3bacc1f4d8a75245b4df04ebefc0d93cd8599250382c905d1e528" },
                { "kk", "1a2bdec375885df75d4b6edbbae2f746d835a861b413b359ce438a9fb82cd2c775925f1582739d76c009f8dfbb6cc9f2e1252fad4cd70bce1b1bc04a1c3f6de2" },
                { "km", "7d8965a08e4b1e81be570d46ae6cdbee43f95d411a306a232bf3be42e1780a61984aa691c7c838b44d87ccd3b71b0b019c6753200a27d18ced4f40c831c8eb10" },
                { "kn", "79ca6316d9f3c1a3895e9cb08f916cd5e42d46c065904c9289c10a65cc037fe2072089b889c3d6b92115d461ad1e205c6fe0962ad84e148a88a6033875801d8a" },
                { "ko", "d5ad6235ddb7b745c07ebef4797cee2f1f280169fd8a29a86e42aa1f205af1d7d0fbb29dcf596bb3f86015264a317f55d5b7e5816dae05b507d5929747e54ffb" },
                { "lij", "fd57173efb235c5205f5aa2e72ff8983fde70546ea85102016dc0a907a8a3fa09b68f028ba3f4d47fd77e4021ac5c5b001f4fa924ee177fb9ba2f6cf77004831" },
                { "lt", "5edb91a06b79ca94e457cb75476e60c6dc99249f6ee2ff0a2ae67c3d4ddbc9eb5bafe3a749e1c18eb519a542836ce32e35cfefd617b818034de1a986dda4e1af" },
                { "lv", "d88e03612523db790158bcaa36d0703447bc00e60eab5b943cab0171ec2f1c0162ae51bf9a2dd5cbdfb54d97895409401829e4066772f2700619b8b8de9f9cbe" },
                { "mk", "988886fbff77b811588d7cd4d7475a557fec21401475c9f09f141ab2b10a8abe3d89dc0701bf4b02f2ad2e8a6c4c4dbc07d6987d824ae1e610ec3b29164b7b3e" },
                { "mr", "54d88f659a58bb19f481a2c3aa0649af55bb26a32b8f9642a742aa7268234b37e16829d0b0988983bea626db365ff21cf4914fb2bc4c5622853dd533af3781f6" },
                { "ms", "674a8477a2d54f73c046c7be831c8458363990ef6ec6c980add14e34d2b5d9a10bdb02f8ae33aad2a929b3a0aeb5bb7c9f6361b6d9b3b11c9e5f5062848464fc" },
                { "my", "881877ff654de76aad1e7cb07ec20df27c79a386e8d89b244f2a918147f93add594df1ac268d25e9a0b66e66faa9feb3036d5718a030ed5b193f075e243bd7d2" },
                { "nb-NO", "fe9d4b69085fdb611deac129ea3c581eaad46c038f4bb29b3bdadce04fa381eff11b5b7a646ea1a9348e5d3772b411191c6c855496d787fd6486658c84bfc6c8" },
                { "ne-NP", "b74fa34666e67fe75dc30ebede7a695e9ed16b1c2c8f21523bf5ab1b2fcce74693e0a015c00dd1b2c0b365837bf906ee7bd525aba97640aea560a434a62f178e" },
                { "nl", "034487320116d2a31f159bb6bbe096eef29e9f441dba77bdda1b8b538d2a0bec1f43fa83a7a4029287df0f99312609dffef13a3d9292f548d181b1effe009583" },
                { "nn-NO", "99d904a015f7554318794054c91c225067c8c77195b042fd62187d0f8789b66652429b099761f30c901e8ca7f544ac0a35c62cab2ee5405a4e2c66898d92d1ec" },
                { "oc", "4194f774e14db40adb9801fac6a8493ad2adbbc94d4c2fc1a5dcda79b683a8fc660a92eb60e0eb2674092c39b70d86d3150f3a1d1e86925c7db29ede44e2f963" },
                { "pa-IN", "e99ddddc9d8b760764118f196ff27570976dca0c5bd73dc734db1303eeaaa036d9813df6ad92f3a3e77f4381971e91e748510c815d9bc61763372b6185dfdd14" },
                { "pl", "cf57327a40ebe7a1690d432d607ff9e55521138b8bb39deb6b5be528f569d92562b9332323d4417c382fa2341699fbb06d2f4b83ad205354201ce52fcf294a99" },
                { "pt-BR", "220afb198acecb981a277abdac0ab09e59e55f9b5604f2ecfe1696e23d4e2ce4ab9052735ceac5a200a82bdc20e35f69a8cd5d8b1df7039638375beafdc5331b" },
                { "pt-PT", "3fb4c4cc88d43e62bc6a212066969d86ed523b5f21d03e76f8ac37907c618af35126694e73f5f91fc3d75e3b3c929e2df4e0a57c5dd4a5fbbd8c2c932312e7c0" },
                { "rm", "8b55d24caa01f6617c972f346c5e888ff212bdbac99725ea134263e8171355805c6673c9d38143b5832a84e4cb1d802c677ce24f5ad1e10443758e8b4893f257" },
                { "ro", "a40ffe89a815dcb7dc25e3fe53a6f6fbcdbb69c4aa254bdf0809f833bc2ea6ae0e7310329328962a66d476f7a163ec573d804d4c9d0bde8dbb2e58692d07cb0b" },
                { "ru", "9d91223f3c3defd2b18852fa55b07269693eae3055af461aa163f81b9ade1797219aaaa2a0dd33545e399aa1c361fdfc83cdbb7da76fefa21ed1b1d41fecd874" },
                { "sc", "6a25f3caa82e2dd7c8cb74d7cf9127fe12ccc8f31b7f54536d4237d243c1421db31a9af5ba803daa331e4a616b0ef89b98073005b1d7d3f3b74b012183c5ae25" },
                { "sco", "95fef0fc429640bf30b9f8b83bfb09dad1d36bbe099c18b1bf667fa9d48c59380cc1d542a2925d1cc5c226a441a2e8bd33e765986c4d5151bb46f8d726ebf278" },
                { "si", "6ec63edd414c6ea5d411d336b0c74b23e6169d2cb9bd96cdc00906cc8f41fb2ed2f14968d5380d2eaf57b0979529e33c5f743b749a1426d74a12ca79ffbd5867" },
                { "sk", "4827cf9e6bae5380be2b55c79e3712612532a54bca35c5cced6561442152b84fa3ff6399ccf284d33220add274347cfa313a436e4cb461cba4ecf92d7b53b0da" },
                { "sl", "1c64efa18fb9d064b7edc4fe256656c39cc085aa8f8776c5ec373248cd808b1774d9726d2d0b90a3ee33e7bde4e016acbe5e96a799ba70b1e1f4f4270d0199de" },
                { "son", "8e2576b322254b85edc99cc69826d61de2d815e1e8254f8cedac84ce4a36b630c8fcde78cb8ff93d692a85e313c5b917056cc5c4389d7c1fb0c3606590ea0526" },
                { "sq", "19e92f44b76c78de4872a2b9a30ac0c7bcc8f1710723756b9e6d018d7807c865f8af6538506e5d2917434f013d7dc2a1848337f821cf7fd0c53d5469f79b80cf" },
                { "sr", "6bbcd80619194d29742f25ac67a2e6c705a3e1df20175769c3e985d0818d15ac4a66df3563ec2d6e3ba61d11ec1463d91756c12f60b5d7e532e3fb917fef4e16" },
                { "sv-SE", "ef76eb31f07884e42157a50754041d8b4c6c34e65e59612fe6e20870712fa33c35908de5dda2a4393b374a5fc08892591551ab709aa175b989d78827b1e8823d" },
                { "szl", "82a63e7efac11b59478beca11e9a860df370b51103723c385138bebdaf94e348b9509e0aec7cc6efd0374b6e0845b19c2558c1245afdd19dfe8fa20ce4869f68" },
                { "ta", "9ad05378087246155652adc906e2a170be1674abf1901d223d87afcb4159b0e5c54746e81052f4948ebe276e3823ee51627ad134d9f344fdfa52b3de6f25ae02" },
                { "te", "b4a4e8102e33ce73bbb6a6dc34c05e1682bab7676a3f68adab44438401112075ef452356030315b0f4c029cf5c89e394ac4e4f0695d8364a8a8b16d779711d01" },
                { "tg", "65b207b2f6b8007d2937ae42b38af3d75461b8b0d843c0d4636985f0ac1cdc89746e8b2c49ad0a4e54d429af1d2c9404b9b6b3fd820e76fb77479202a7ecdaa2" },
                { "th", "1cf0947c4c3fbe13c087a16fa55992bf3e803eae6c188bd2e2ca2fe7f94956b8eff0a482dcc0173ae79df4202b662372bdb1130fee66bf6e9dd5717d3803cce9" },
                { "tl", "e4eed83bc2c664bbeec24bcb9522797af7e14904a946f2c1a3439878bf30a376123ada2b9294cf709dc340b8b2cfc9858cf988103c9a61310b5526d69b3931cf" },
                { "tr", "f6f0060dde770938b280005d00775b0c81d3b2297e39589dff82734cdcb3bb71e295f1d77116ce16e414797c0c260378dec7313c9debebbf63a274b1628fdf04" },
                { "trs", "62bf49d7ad22bf2c93d77c9a288bac4b1141848b95464b5612bab4341d229324c3fd0001bc8b4920d4c2d343dec870a3e07fe3c317197df06dde2b2d7d67d3c2" },
                { "uk", "c65373b7cea8249eb7983aed5f10e60bf80dea2ecfb2ebb26bfc3f6b1d156f182b848bacfd86865c3fdc1b64c50032a54a92a0a69f20d4a2eb74d60574edcff0" },
                { "ur", "6fc7cc766c605f95d568696a8f39f780f9c4b7754972fb8078994a76f9cd884d3825f46f80277557f99318452f88af02a8d2495061e66944ef848ed0699c5463" },
                { "uz", "03de5a9cc7bf7f14fae1995a2eed4747e8810f2f432ee552a5f40eb4afdab68d8eb55d091cc7667fc0535570875a11e41c2d2a259cd7d1fc01706669ed9e6e2f" },
                { "vi", "49f1a76303d2928d1a4fd36de35c204f6acc5bd21e578b1fbc0bf6d89eab6e6c9695b0f3a0f78ee47ce4fda6714a159529360dff8234823876aba52fb5833542" },
                { "xh", "f6bd3e6b4e914e8dfc098d7dcf8e8fec7593c1aca19ea9a3544a209fb1cdbf3409cd535f4f7f345ab45f7a2fd6ed6ac64c8c1faaf842babc1cd29966505ae349" },
                { "zh-CN", "14ff1262f1af55b69f81f03d1d1f5b5e1a6f1e1416fe9786e32de965d3517a3ba8161f61e72329b0c483646138b5ddf9187e654a1291086d22edf7521d5c126d" },
                { "zh-TW", "bdfcdd41f2971d87f86b12c6bb516170694a63dfd1a0f5a45d1ac692e3609b3cc1031ea06cf67dc846ef274fa0c47568eddcdf7a9e12bce2a857c8d927b510ee" }
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
            const string knownVersion = "115.9.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
        /// language code for the Firefox ESR version
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
