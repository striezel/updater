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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "128.0b5";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f0a8d140d71b41be6ff7b21c3651d8071421628a497165e501d873587a6a40351578b64959b3a7610e56f81055baf1e452fc573295a5291729e0f1e80e2cede9" },
                { "af", "baa1bbde254e4ffd1df99cd2573d1330419de1fde8755b4e1ea20fb56494a848e5131a79803cb55c89b71c580e1faa08b179d36716efc91014e504dbdb4da48c" },
                { "an", "8e1a735b2c5013e0def2b226abde7d63774be27d53af9cb8de75f85a3952efcc9419c06eabae737fdfe4f37fe30707ac252f1bc29e2c76881e559eb86c1d6f86" },
                { "ar", "75e3dd4a0546860ea5c82e4b210427ad3bbae911ad6cd2a9aab83d4c5d1b7099b5a8677dde9937e6516eff8963839b9da8245fd53e2a0e0a2a92f9e3c2b05963" },
                { "ast", "9a0a416a7fa7d8b9fdf0201a3e8cd97677deb96898409743cee573cdda51a0cb3488eca760b60bf7f513938b486b36a17a687f888bc725577baa6ad015cb7940" },
                { "az", "0e3be292dcf88d5332b3a0d33cb952143e6e7f75148e226b8bfa2c2a01f569d4db4ace4d878ddfc8e51ce34780923f7a5202ce69870a5fe047a77cd2a13d64c3" },
                { "be", "741e8092cd2c969029f35123e24f93f633a3434dbbbfe0b59126a0da3b4c048121df5411f94d62d906bf45922dfbe2be1dbb3b56fec6cf81ba62acd20994d3ef" },
                { "bg", "f5479045d83385726fb154ade243866f01149a95a855c80291ab299209cb01aa7f97e8409c16afefd0bae7f800b9aa6bc396ac574cabf13338e153622d9af52e" },
                { "bn", "8282e9606ebe16275e1f942f367e3a31ac058554ada8d6154c978ae63fbde9f8d80716e0abeb0c500d760ba08b4e6f520bab04227c961e2782863a328cfb60aa" },
                { "br", "a4f689156b704ee671bef90f25b8e85b82e8819633aa234b08fd88dad3d7c502456143b5fd7be364a51dc5721f8e382fe2b7158ff829c13a70d991718064d681" },
                { "bs", "d981e2517c4d38aaf39d6fd8240bc051375afaf2ebd2cc04974082139f803b8d0166b8332f5d3d7f36ee14382f2cb404bd165443150b37671f2a4bb6719ea2d4" },
                { "ca", "1e27e92d1fab360f55e5fab915573c52c27c204a885404c319b5bd0289802438c5ef35bc4feee006215037eac3324dae447b67d059db2f7e570a18540657c4fb" },
                { "cak", "a6302e5bed70ea928c3431bec8724c224a37d8558edfbb2bb2dd9bd605d2d8cb819f334160c86488623f8cbd301294568beff30989384d537e9d4753b6bb6b7a" },
                { "cs", "368f5d593c4c52977a87a5610fa83889dc49571932aa80f5dc9a7c7670854be8ab7c57291a402f57494ad70d7118cd9d895a4e97e49df010f4731eefad2bd0c8" },
                { "cy", "268bde46b3a61586e1bb852fa76da414cd5b29e3d6979d87daecce16cedb143570e3991ebd45d8038dc62cfe579725b3190af76a0584303c8a1fe910d1c4e082" },
                { "da", "9f1095e0de145f86407c309c28a3bcbea158df159d791b59361f852a07b81c0dda6e5fb64788d8406655357b47b2e5af88b09082d8a6e31fe2200b4390b2bae5" },
                { "de", "f368ad1cfa5405b1a543288ff6a1fdd49c9e17e711a4c9c5a4f4ef9e1f8338bbdff90cc99b13cd74546fe495e06e44337ad9e8a7bd35eb6a8442ad4d7bf7e893" },
                { "dsb", "5dbfd5e3b448d2a749be07314fcfc83ee888ba0065e03b2ef8055ab238d4901620e4a5ced98e651be3ac8590d00e7a54374276cc2e6ccdc570da837aacbe7caf" },
                { "el", "9e1fe1eac13cb276a05a4da32ff00d067eb3d5cfa36e9e08edfdbd4eb4057d7ccf91b470cf5e0feec3f2292ec113171017647e936d78fcda3e6c1044d2121a67" },
                { "en-CA", "52e60a8018d50d3cb6498f698ba0a00308cdf7ad1b66920d6d5041df5486e928dfacc241fb945ead50f850ced17a1f622b9dc07889979ddbd976543e62fb64f5" },
                { "en-GB", "401c8adcb69d8c62a7ab1a08936ca6f04cdfdcae8200a26289910807f29152d1c869ed7e897f656db0fe84ab90ba102463f7da6ab829a5c6fb7235121ccc0b8d" },
                { "en-US", "97e6d4d16b8f746f4d300b956e87c1800482507d44f6999509ed34049b6adca406b4b50bdf4b5b55c8fa0029f2fbc3b911361430662fc70db6af07279ab3c157" },
                { "eo", "cb30434da7512b65cc04cffe567f1434947fbc2d7d85e4af4d230500cdc24e931a13c61a8dba909894346e428fc9693bdf6463dd686b7ffee9b6f1749f6d1460" },
                { "es-AR", "56a30ad4b8471e95298ee57290fe9956cec28c6140364fadfc3adff0e571b8c28413cb6000a19007605b9671c3c06dc33154f8b247fc8669bd2056b12e30e19c" },
                { "es-CL", "dd1d873e0ca4e85b36521879493f48aa97f823d4b9699640031dae07e8f6b050ad25232353ae79ed35a6c1c7a5b4beadc43543385c8506715ecac9dd28266dee" },
                { "es-ES", "dbd368cf3200ed116f6d9fea6383f415a89b9c69ac5670617670f6a7b59f48d6ff90bdd3b422bbee7fddb76044868be00de8b6db3c65ecd881486e3287b4a475" },
                { "es-MX", "fbd3135533d46005568f74ef6fa7ef0f4d78cf409803dcd156f3e4550a95558cc79915f21d14f3e60b18d0ab5847fb62403cdd0f130fc4755dcdea2612ee0a5f" },
                { "et", "93a11a93c0bcc6a1b7ef8ecd51a1261c2c671528acbf4e64aceb3130bb21e56cda219e82d9e316f3b944b0daf9a07e618cc33edb1d8aa0b3c6cfe418d005fbbb" },
                { "eu", "fb2f32fee1be5fdc4451b026a129cbe906e2cb4a642f33d5b35a2e936a55809d95f49149918d70cc8e07bb77b183d97178303bc9d84646394a524e18c1ce1bb8" },
                { "fa", "8fd0812c4ec5bd63a35e6378340057621b82c7bcd67a79e04af3fbea75519a45282c9400ee2d5d2b17504953ffc2ee5e50331839c3c9cc436895361d03a7a4a2" },
                { "ff", "843b34bb62e8967a3b59088ba2fbbd88297ba8226e2e8a324fb709a83f96b9891c052cf8aa963a1bf5cfcf61b58ffef40ede50e4625d20dad41145d1efdd4210" },
                { "fi", "69f8b69980e0c35e7189f107b01c0f616bd3f400e28d5f7eb2074cb834e96acae4189c5fcbacb7786fecf9044643f4b7467c92c1ce249eea25817f1e4b3b258e" },
                { "fr", "513ec6a3c1408d34f7177214bb7a1da00182f66969cfe0adbfa0c402eeb4df357fa8195d70655d286efdd0d8bfbf038eaebbfaab71a7bd992675e763dde174c5" },
                { "fur", "8cd961024c125aaf84a3f8bafba6198d9c9de68124e9486c3dbb3b3fb1a4a46692b7de86eca306662469abe2dc3f210a582b451c74f6fa4e549d947cd7651712" },
                { "fy-NL", "1bf6b8c5a03d5011bb97199c023a18061ae0f2ccb81a2af4552a7fd11dfedd37dca8355d94fe1aaceac2967c6835ba46f3cc06115d25ab18b44852323cb429eb" },
                { "ga-IE", "248d3a7160ce14e130fd230a71f527ea53b11b29ec1250691adf71ffd3638151d668328fc40389dd8f05d7ec24e9dac7139b17c1e6cc83121354139135569bac" },
                { "gd", "dffa3cb4bee14a30604d9d0af1752329607f1f42173a65cd6b4d6e1b7b6e040d7fec48ba0fba8348ca0ae45dc2bd162917b00847713412cba49cee43b35432d1" },
                { "gl", "8336ed1bb16f297128421944b9a02d0311a5df99f887a11c0e5e1c8826b8d73590b7b3d72709256507cd045bf66b58843938867446bfb1d6b9f10810c125d277" },
                { "gn", "d5295e67ea733e9c73adfb4be4d293a02db9b32de3f675c3273b833998e17373ffceb226263f2ccfef240e3af21b0614eae89d26731a2c1ce5b3975535e0aa1e" },
                { "gu-IN", "25a64cbba2eb739fbab3e89ab67edc23c0de59c17fefb9925b6f1243a83c82ed046e032dee87f22c1cfe147cdc85ecaf7728aad91ec2f584b39de92465a7b0f3" },
                { "he", "2840353aec53649a0d7b9a831045073cd38b768676fb3d070d70c5cd64dfff6312da77f6ff62bb1a49bd86bb9d59d8fb0a4f6e810dc00a9e97d4b53925db3b7b" },
                { "hi-IN", "c0f571c27e8c0278f8f65c5903cef8676144bc53afced7c7fb2a5786f28e5441392994c2a4e378b87dc8fc12d70ecb3cb58cb2f2b4551b1422c65032dd2f429f" },
                { "hr", "7438491c5e6fa3afbd0620719626218b445a73109ce249f7ed25ccbeb1d5e27a0277e502bd52df0f147fe9877395c57785da3604f0f3830df751aabd994e0132" },
                { "hsb", "e5cc2e908c499a7d2ca9e4810185a7aa2a9605e5e65285657cb3f75fb141ef87ff76a4fd8dcd2181d29d37754be9d9b19a75e6011fd3e2b3e9d22dbdd2c9a6d8" },
                { "hu", "e9a632b80a9b7cd0095bbac074697d10f038bdbacf5bd3bd2f7674623fb20e09424c450bc3e8894493d2c7ac6921ca7c73e69cadf4acb2f1367044b59f412e32" },
                { "hy-AM", "9cc896e71d3e6f994654b8388a30a03beb0dcfc001cff2abb04d686752c4eed0f697c0199b42b85443cf784db57e3e773236dc70cc4a01907a5e052244dfd622" },
                { "ia", "d4782d2805dfad27fecb8ddec3687efd26e69d3dac01f091d6283542d9f6924681dc79efdb4d548b8f1995018e8a00f4f223bce0897ce510a8773b68983e4747" },
                { "id", "23890f9f10c5a126cd9e9f21c465807309f105fcc05d6a78ce320cd61556a3660f0a4722cb2dd548d12734f5f810d522b161c2f8d6eab4b064cab91e08a59f45" },
                { "is", "a4eb874ab4b4594d1e4b20963aa8f89a1545cf5110c7810eff2e8f65d8c9c8617d2c569046a823183b8b44280b7cf8f2842658a507b21495a6fa405dbe762eff" },
                { "it", "4fa38a80e93e0de3541bee2f2e1b696b484b9bf640c5b17d0f66ee9d42318a2656a04c03bf753d59240881c2f89d6612d3acca82a8efedbc2c490dc6dc967c9a" },
                { "ja", "0bfdf7fbe7926e6564e605fb6985a745e94dc1e55f2ae4ffc856e8eb0f35f114b001217900cf050f02d8e928dddf6cc97d76c665e5842b5de0b49769faad6983" },
                { "ka", "a164489a5f65a1ca9fa5444d24162f871036e79b9e05ccc006c1b35c409d419fb21c56d4ed9f1f0d553136befc3a4f62f1ab36af1de6ee53d8288cf8818c82dc" },
                { "kab", "1b1bcaa6a783ce774fa4e3700f61fd4d35bae6e676fbc02f59d7f0bf1618e370c8bcf3edcd9770c2d964a5d2199091fe16f9c3557ef255b1799580d2eb740d61" },
                { "kk", "cf3371660c2a709152b257cf3cb16ddc169ea9d1448bdd5fef8fb76456ef0102490206c551bfef06d0b0a019ec00bfed21508c036c8c9437ece69ac6d843de2c" },
                { "km", "a3c471603606ac37999bae9897ce95403c963d193576683b7a61d7e8f89efdde418eb97c6e28c5473fb292e2571d0b017b7191399d2c6c08d19af2eabe6464cd" },
                { "kn", "72aa67ab21236e951b4640f647a6526d1402bbad839304403a1fdf973df3328917dea6618dffe0f3f6cf0915c6353c958a8011e6e2fce685fd5c64d0e1ffd63b" },
                { "ko", "2e6644eea22d2494a6cd0d727bfc58fd510a731c2d2c5a988798cf3f261f0b294dd91c39241a2129fe43d4f483f29b4b6fc6003e0afb62d5767dec8711650153" },
                { "lij", "c0a3b55c694f59b26c97b1ab19c3a5a05304f6992c2d90b881808dbb9cfd1494a8a4815faeeb2657dc373cd86151f6fa01672d31b9abd84d1193172dda4cd22b" },
                { "lt", "9bdca22f9195fb5805d136bc1a08c90f0fa53cf1fa1fd7ea6b171d79c9d35b3c16d4a02f635f1932c3510833bdffaf5234a6e948d949d84d2e4f0ddbd477d62f" },
                { "lv", "d72af709c4508cd0779f5c75bbf9610654d8eb98b22d4123d41854754bd4afc487e81cbfce350cffdf8d8aab8328030ace5a6a913aa39d95441dce5dc597578a" },
                { "mk", "5dbc694850df4f97ced47e8decb2341b79a2a4f98b947871d019abb21df979c898edbf77afc587aa57984f888f82d8cc0cb69fc919e94030e081b8bb085eaf84" },
                { "mr", "6a45efb908d406ae7545fc6fed85a05ffdca114300f4e92014a6c33f6e6237c971b669160385808787790ac853378fdae59f7a388dfc1624b177a32454b7615d" },
                { "ms", "28042f0b40ca116d465b537359237c0a78413c545bdb733e93b97972b1f066dff603929f7b4c5ee7d7b2d3da291069f10d5a604d2d2919a1f1536be0e7fd5050" },
                { "my", "c4ec739f7deb1b8bb12b6a33ee662bb1545c23916864dbef85fddc458eba247eefbbca5cbc276609188c7e55f7af824fefb9e1ff1e211734257343cb00ba7784" },
                { "nb-NO", "f94841d2356fff78a8cebb013927337d322b65d6cbd97bbf0a37373c3633300beed96c985532f2abb906fa73886541a355dc729841bebd8ae042c2cdf007ecd5" },
                { "ne-NP", "7c95e79e729091a90181087f327cce61d145c3a2325ab211634940fd627a6f4d2bef4bf08fce4ba2564938e112bfc347ac0f5906414fe2de437cc464df95f604" },
                { "nl", "a1dae0b0b575e6843566619a1c3507e832da035a3c37373c16041dc7ffda3e495470ad5a58efd2cb2dd4123ddcf3c5117efc7bec73a8bbfbd44355cc98d9054a" },
                { "nn-NO", "3ef03b512494644a6901cc5eaa45cbe7e45754f544ea63a2e04fd127e72e4dbb89f6a67da832757878a002029399cfaa4b0aaf6b29b24553fd04b58f4afa4604" },
                { "oc", "b7e5f53170b55f19e146519f70b40f09fa2643caa5ea2933d795689ef467c9cbfec3fe4ae2ce709276518383c1f72be05b55b1be9c63d3d6e3354baad4dcbcad" },
                { "pa-IN", "39b7cab0cf529976980f1355c3c648b9ae96eb7b4ca59bcbc59a9e12ef8e5d26b59459943d01eb02b1fcab2f75ff1b4a20ccfdb74bc4effcba94a5af77a82d8a" },
                { "pl", "c60f66208f303d05f9490e05eea8fe6a34e73f4d2ce0e553ec1baf8d81d410373c6cd94e582818f95802605291ead2b4ca02fbb7764bfbf4aeaf13835f0c903b" },
                { "pt-BR", "431e21024bd245e3bb0fd182cc52182bec07db73971ccffda64b1c553a866ffcb7cb6fa5fb20ef0036b5e257ebd5b8c2c052ee9efaee8f5d84ac3d7c453cf5a8" },
                { "pt-PT", "573facab5f2d4266f8b0c77bb14598322327d2f91d403bfbeec418af52a4d34f1543cc454b7b847308e81368216b73b6293d776407890124f4178bfb9753d1d1" },
                { "rm", "6d6ae88dac7334654ba688a17753ce3abcb5391e0d0ed44cb9dcb4604de32167c19cd6778ae88cd2667baebcb1f25a718668a3bd64a905f59a35ead441aa625b" },
                { "ro", "f2153f118aa7467c60dd469faa8465ddd14f70116c20ac06c85068407de9b8bdaff1bd2e3bcb08459601760028a38f340933e4eda7585bc6f0a9394f6a89ec23" },
                { "ru", "e5c00c2def87ec296a963ee738895308996a49fcb966009654bffab292e1c72e5ed9f456b8781bbceb0212168cd7678df0079b78e07eb11850a2a049b88e3af8" },
                { "sat", "da042628a2d7b11516056208b6528b155fa64116251d80390b9f423abdf05dd8ef12911ff00c9a9ea7020d0af2913bd86a659959979777387ee91bf801afd0de" },
                { "sc", "2d0f8d536608d5d8bdc74ac94d20e7d881eb109132a801f67a5b5790d2a399661298d23e95588b73804ce2e5c11be07619e1648a52da3c86a242d272a55ff968" },
                { "sco", "30be4973150d704aa4e5008b1ed50a0e9f405d2db417a491b4ef528faaddc663eb37a6abe7f1d6b75d93b51d99288ed6ab050109e65361e67fca0407633d2679" },
                { "si", "18077055662dda2116a725135eb75229be3bf3c51a9c3225193e8fcaaf4b742a3a7575841e49314820655d6e9d27676aaaedd68af17a8e8e4b4f60eb9d15d834" },
                { "sk", "a6966bd16f67b07f1805bc97cb8534eccb04ec942ebafe2b3727afddaf0944dc2dd356752a6d3a6236384a52a038cd78d415526b91376d17f64725eb1d30923b" },
                { "skr", "59b2d4d3805295717af29471fe20db2cd52365206dd889442938e2bdc4a2691389f7cb4b35aaef601b234f2ae8844b32cddef358244d7529e0c292f2dd89b8b2" },
                { "sl", "8e74e65bb2e6749691abfd2d47d33136165415d09e944ca6918ffdf746a15694ef7ce339b6c5a24a4ec7d43a22891b8d1f918241250b2ecb3457683bf9cb3a87" },
                { "son", "d687143c34773923e4631c03b7df634def55caaa8fec34bbd10359edb9640b30bb28b761d4d5259ca568f6ccfd8997f48c4a4372fcb76b2e2fdbd7e31ce9bd3f" },
                { "sq", "ee595636d49f3ec1d5f679cab625d9642281fe5ef6ddd319217482b5ca5ffdf2ecaffc1445af5a6a331ff822042b926cf55f92724005c672321bcb120f286e28" },
                { "sr", "3d9b740afa59d1bdab663c12a5a137fc1fba1b955901acccdfb8cc16e608bf2f8fe33815af8951b8d5e125f6e6fa59492eadd233c9e26b4313cbf34c4c8212ff" },
                { "sv-SE", "e7006c98e5244925407a71d0cacaf3912cc1e3a6d681bbe0d06dc391bfaa7f44239b97919734ee0c1efb29ff637f207017b9b3baf21319ef746a1da84cd420c7" },
                { "szl", "b11a333b55c3903273dace54e5edf1bd70abb5725e68ac16281397ec53b5e89856b05a49277e27019348aa220e8558aa642fb0d4ebe2c73984fc4824a2ef3b31" },
                { "ta", "56daf196083ddca2423d93f9f0ae6e821d6fcc09b461f8cd5ef11bbfc86e548730658b2a5a0eb4fb92faf8f7594a26180079dfecd91a15bf3d9950df817f0581" },
                { "te", "8011a85f30d1f076da4861251975ca10d4a6f9987c40529d818b1b0ca9f5091643ce1ae0268fd7d32b39b69e5c5dcb5e071afbb50ad5700f1f098c079119d8e7" },
                { "tg", "0afb1c0c374cd5d4b6b2005d4094c488c888e5be28016200b72c19f572abfe1cc3b766d029ff15459b5be20d9a28fa20425d75a2ed7004f0e84abfa965768efc" },
                { "th", "6301207d6b386f18c0501ed654eaf2faea185a6f90a29532f9308c91e7157fb868df2e6472c175544dbb3dd15dab50a4ecdb534de9742f08c7e820ae1e9c9f61" },
                { "tl", "dd32f445f14f9b58e84ff4fa11f78a320b39f5c8b8a045450894de43f7558bd44e2697555d7762184695a0905358725c3239b8b9087da4a00d6f5867b5924ec0" },
                { "tr", "307f12937ce612dd6b0695abb09d5ba29ff296d8699d923117b41e0f8ba04cc7a9265547dcd4d4c3f42f04fe787ceec953c9ec32acd6f00d87e1972dcf13c6ee" },
                { "trs", "81884803221344283e85c19b5d70763477cd6231fea7b2602f2a41cdfedd6f5918561f4ecea42fe69ae51b4653588b0d917fd2ffb6e8e210fbef761d23061802" },
                { "uk", "d5e55e4ab0e0c4fa10b2ca9800a33991bf44deabb89b5be871715c617146db5fa5fce72c880624d7c9ecaf0bd79c6c53f5e9c801c2a2f4710c87fb7b2ed7f57f" },
                { "ur", "81cfa4fde50a58060aca596fd4a83ba9a9a97f1a50d32fa92a6038f1d007d3161db1ee4709fb14127ae11e716bf05b98a7566f23ba5de9e97cec840abd5a19e8" },
                { "uz", "6519086b003141f1618ed0169e2d4ac0de3a66ffcfdd76476cd2e8819d50b597c752e972d55c23edb4ed4dfbc292f8e19d2a0fa7bf5aec04fea35f79f911c9d9" },
                { "vi", "e4ef3c0410aac9877be16278a2fdf3b4c1f44abadb0c73a95cb550917d8fa7529b18fe7abcc86cdba7967ad27f46aefd37387fab498891e5fc600935f76bc6c9" },
                { "xh", "e00f37feb59e8f17ce0c35a044a548d79e428469576f8c0739dd8416421e7f69e7c53db65ccb827c82109904b9026de96430a42f3cd7cd137e1275de07ec6391" },
                { "zh-CN", "f69ea35c8e3a7bde92997c004c3f3023910f29fef56962a6cc7eedf94a75748a2561620c954368e450e9e5fd2c2b03e7d040e66fa47cb07194c837e69e7e70b9" },
                { "zh-TW", "f1410b0213baddb448053ef666d45a5e1ca776d22ef4e841eae7463a8b158f08d8f24ab961e54595bd3cfbaab21a828fdb88cf657b464ea145e1127a46f81599" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "df6ed20f4e1fd2d2a6066c1db41cd0ad7690ee2769c8dc471045b3304033cad882c1733491dea72d04ba4309c3ed6113544019b8bbf8aa60b2c4254c34f0a91c" },
                { "af", "b497eeec8d8b37dedc3f26622d5bdee7e335af62934e0ef84865166abf79adecfc03363edc908ace96600ef2deea223d09911a9e755b565aae5bc0acfc52dd29" },
                { "an", "8c77594e883f5d12a381a0c216387e07aa9693c26ac392a75e3f508bf9a3f45e6310caf7e8d07c69f539f2aaa7dfa3c7b277b8195789d82df60c1c6a3eea47ee" },
                { "ar", "25eb3feefafe605f89658a0bd868a6ace745958a84290ed344899cc26f0ee54d28a2c92ce3bd92ec9765082e6ffc9d6d00bcfffecd541d3a34d78772a3b18396" },
                { "ast", "9da8e33041c799a1d4cc265d27f552737e5ab619056af1a08553a154f8c7eeab9863a39e7a2e895ed1f25629455e784eba184fa550d8034084ba2dd16b5fcb85" },
                { "az", "f7c77fddc2409ce6c89032535f839b6129258027831b8929cb9a12fc59c8c242b8af95f9168c092ff2597803c8fb3171a7a673fe3d0830f9fbcb0c5292d5c642" },
                { "be", "e2510818385796635c54ff50fc94235d7cc5573cc8b17b2026fa8310a03b2220289838a83ea16feef0af732bbf85b8b917c598c6cd5764a489d4a85b0cd68cf6" },
                { "bg", "3675af973720234d0a2cf8d2011189171c3c80d71b6f76feda83b945a525d16c8235eaf1e5e82b4e3fb38e6bd7b3035510c671afd3b97513c9d5b34e1fad1852" },
                { "bn", "0ab63d3c1e6d3a3ca015340b2994e1edbee7db5e379ec61027157e59b4050ef9ef829ce59edebb92570f2d382558e4019e22a4b4a8b94f9e4a4c352483bc74e7" },
                { "br", "1d47a74e4609240ecb737201033e2812e13afa49d27bbd25a7ee9944676f0df5162d942048029e6a8bdf4e761ec31cc9e051e53bcf2b0cb1d3477690dfbc9e8d" },
                { "bs", "c35dcd43fab7f0cb77fd1faeae61735aa0dac7b445093f6e02d2df4c9847bd3120fb9cb6e81a5c7c628899d734a7aaad374b1621470cf7c5a91d9bb8d5669904" },
                { "ca", "4017e89d1a9b9520aff766ae5fad2dab1ccabdb62891c6eef545a5d779c13f718074de61847d5f3ebcca069bdde2d923c5297e3f800185f8b36003d16c997709" },
                { "cak", "1136511ce8f73974f6e43eabed68e7521c8537b8e3bf773b9bf59afc3634f6af33717ed474c43427913afdd9f441d9f1744d8bc1182eae856562dfeef04ac4b5" },
                { "cs", "e1e8d83fa45f23e9b7f5c9be723218944623cb7eeb642cbe636e68709ead8a3aae42a80e8d7e76a116752ffcbae4c8903ea21b8f2696105dba16e4203eca8d60" },
                { "cy", "2ff3bfc286f1c46d08a1c20d3e5a70f4b143dcd2a996c983ae9ae9448ce9ce4cdae5d307f53209eb92899c1508d0ee3245f4b61d19057f9874787db7de94f4a0" },
                { "da", "be162c59730ae2907f7ea2b84a2869fa4063a05dca4b67ec2c30cd6488120dbf711967c1c4e4ccd22dc76c0f44f14159c27206c4cc0eb87853c9e0e2f91e8724" },
                { "de", "cd79fdc0f3dd2b8a828571e21e3e31cc51f72eba25b35f9a7a96e0f3dd78b2166bddfb7ff2483ceeb15fdcfc15c2921ae1d02d716ecd8842582c0befbb6c0cf7" },
                { "dsb", "6f97a763507f7d5d474863faa0e6ada9d9518a17c1b5d3c3001a65d32a1aec1ce40ded8bdb43a8b02daf9e16c2d1834df8715f13768e2098a628e8a29e9f822e" },
                { "el", "41f980542a64c38b8078a376ce829f6f4b99b11170a74f21cb389e5f350e5a96aa7335492599ce1861c060db82524d6884f79475769bd0edeb923ee047522d79" },
                { "en-CA", "5d2535bd56b46252fce1d0be6ea97913b38dc75bce3b5ad2c469ec26df5ad881be5a653a4010f96af3e6fe312404a54b6f1839a9192a333fc74265aef50cee28" },
                { "en-GB", "374adcaa5028c8a2c004ed107f46e35d29e45e6a364ce0e092a21a375b4c74d906dfe7d67767c749a06c769a56ffbe508b7380ca0f6d64f8dc3cbb4bccef1c1d" },
                { "en-US", "db9dad82b1a5e0e8edac9ce81721c15850e65e48261ed29781b2ede36b0cc72370fa0fc19cdc3c1afb1a2eeb1b1c487ce1ad26c2aa29a979941b6dd0c0298841" },
                { "eo", "ab383ecee209aaff48d36c5b17f30a9d27c7cab84cb0fbcab4985ca2d514c82b0ed81e5ae3663935418a9097cdda2af8cfb33e6f0089f52756a2ebb638766748" },
                { "es-AR", "bcad2dcb11c7fb42c4e3a4a0398adcff7857c83cb7b826c5caaa0ebd46299777180eebfe698a09a49e3e623c9492c85bec8277eb44918e0adc083d10d4563078" },
                { "es-CL", "b60a4ca3860dd1cb4a1a28408d02e445605445bb871a820840715c75a5109790138224d9b1ae10152dc3d82e1880bdc98266c42f567c881631d99463d2556a3e" },
                { "es-ES", "34b9622c9ca14d4df3eeffb9cf817dd075fefdd634b371886889ad00a7ca11636216372e17ba686c139189cc5c25a5774f159e5cd60d2296725d5dc7ce2f3dc9" },
                { "es-MX", "c00d49cca361de7e427b85b6558731a6c4033f37833ff134f1c7d7c169353bf95849991ed6194434d710ee6dd16734f659be316f105c7c964bd146f2ec689c97" },
                { "et", "73a33bcfe108aba8a4a8fea5758c8fd587266eb70ecc06c9dc1722c1e4cef323c416047021ee91f5c6b0c2a746cdffc75f753683ebc706d485bc76af43405a95" },
                { "eu", "d795d362aaa2f7b6021283482dabce8428db14aa477a2ba3fe9407d454ff6644bd54ed8027a033f39ca5b0d36727a9b5301d7c281d85255819b3296a27acbbf6" },
                { "fa", "33ed9159ad367a8dbd7e4463aa9d24e822728da119acecd4c2504f6f6f08f6f52229ae3c42e775a48d1761f8ec00c077eb362012aed8d423d5ea60f86b6698ea" },
                { "ff", "7985365db7f3ac5a28db35e0e75486295321f9089b29912d63048d56e1c752cbd5331e87aedfa9f11842538c1cc3ac0e7747cd623bd56fa5efdca4c22cb53149" },
                { "fi", "dfc30c49fb1832fa32d37e8209ef806f3cfe8f0e1ed87fd454b490016219fd6900bf4409115eefd3923e8530e33ede6e97041f17b6c91e9c9209f217a4dd7eb4" },
                { "fr", "66f8efc4f931db5b58b498316eb7e86a84837b4fc7f2cbfc875213a35aaec6bfd54127b47e6be97f80caab05300080b26f08dedb0e5467fdd86a4304fdc829f2" },
                { "fur", "ae1aff641e2b144ed4e809bd58bc6072ac77c8968f3743bb42399522be19c2c02242e4c27a6f7da6192ea392a55b1b997d324a2bb3f2cf2fa1139daa483ba84a" },
                { "fy-NL", "357cf033c1596f68f7c3c20a616302b92463a184e7ba000df57ee581ad62a380533a5b879311315a8e83c46915573ae83d266379504d7c7f70eff163e4e3d969" },
                { "ga-IE", "d3da4898260c473f2dd351007881d398be030671bec96ecc97756285287dd4586a34e9ceb0206ab05c5ea0a74d4015ae3cd04654d2cb94019ff3366fd3caf52e" },
                { "gd", "555c3257fec12b9e9696a7961fea069945ad392796a447931c44d2b2caed35d77bf53367519622413246a2031a70b5fa860e1c35aa556a8edcb06230898db3b4" },
                { "gl", "d31d817259ce0df1d4aff1e4df5bb3bfede055943ba92ebdea77d055a4d0f505963fa64f32c0c2f3faadb91b093e2b2239cfd0d1f9628464f6db7b0a87ea6507" },
                { "gn", "30a863bb70e2127b85aaf00232f77311720874687ba3b25894f9f4c60ff41cd7eb40f0c0596603d7b178941d4565a33dc8050b27e92a13ab9845cf30b5f52cb1" },
                { "gu-IN", "a9c9938699f5e43642e871d8bb15b98a3dcd571b739dbf5f5cf2a7f608055bf9cf96425ecb394a798463477acc17d612d971882e3037579892442714e7b540b8" },
                { "he", "20f283745a014c3716692b301089194145bf81a25d1db68f72679aee7832188c285b206f4a8f2dbba2ab82ef7603f14b296df0f177567bf62ec823898ca6f7f8" },
                { "hi-IN", "9f3727cb5c601f536549890674e56c037750b230a8cd3cc6c5949cc562134160312c56f1192150fb85608bbc511b517a868fe276219707a4908e2656e4a60d07" },
                { "hr", "c95657dc619c0b68cc3eb08bab489e180240686d4cb278a5599915e16e5cd0cb08b61969dd09d05d7dc4679ea12e3205e481020ac2353897e1da10e66283a1ab" },
                { "hsb", "7791c2094552987223398698ff3674aa1d8ecfb3a59d0c0279351dca10d013f87e861bbe62eff784ea5dbccc43ff3fe6a5aae53c97043c9a30d42a7e70104e42" },
                { "hu", "3567a9baf4e6a6f2515c9a7d0761c2bd3b831b2e07e4d0f136c30e87f5a062dc26792019cd26441880d3b3bbdabae4af8d66838b1224ee202f3a470b8443d660" },
                { "hy-AM", "2f4832c80c660e33150eef343a45b793c5a3e39dc7f6e33c61ac705564ce37785ce16aa2cba0bf8419e2b6e5f3412b68674de0bdd935643ce25ae1a878b5b80b" },
                { "ia", "98e62963c1656733dacb3961a7e6afadae86b3940f967d3970919ef544b5bfeaa1d05a3752403b747a9a40cd3ae637087999d480c431052757b6cad8b4bd1023" },
                { "id", "60196e2663b49ac3d677426ed7150eb30bd5164bbd9e7bc79a2462fffda530d1cb28e25b108983a52b6e686876f59c77064790a68897b6785a7e382646229dcc" },
                { "is", "685359ae554efdd3ad13b6290155c5b8a0bd11692cf1828e2fe858b865495522df9c163ea5132077740b323c053252384c8360acec8e2b6ee3573bdd7ff60000" },
                { "it", "c138e042b6e0c1a0dd58fe3f5b092549da96112bdc4c3789c1ec7af0d989c481222720bdd3006d2807d4bc458471057af0a157c310c6136d46d08dcd309d6d93" },
                { "ja", "829166d27ea763dcaf204031421cca8813817365f779a2fdd79cc3d0d0187be5f78499b78983a55eb0ff1218580a1fcd58dacc1bbc7881e784375ba1a557ddde" },
                { "ka", "02f699afc3f919a04750203d5ca4a84bc78df651013189e9b5cea9a37098b23adb352ba6c2f4fa6d2b4c2d96128d042bf6cfc9c859eb363ffcbeabc503ef7890" },
                { "kab", "7d9cde244e8f373761c4196de774a42c4a14e0d0a00739841ec7e24f94e92855a8899a7b2eae165ebe5bb63cdd505cd039eadc8fe60c60f272b1fe1029850cbc" },
                { "kk", "1a19f35580f99603f282315f4a6cf0f6b49c24606b3afe852705b9d44f9105114c371aee472c182f0fc40558294c4ff361567b12ce2d120ef94986992d74b35e" },
                { "km", "8b2af24b86375a5a7fce4fb1db58bdd5c9873c26fbafe82cffbde2847e7a18ff562d173762c3390829a5cefd6cb7431757d94de485e8b4bd8d140a15b7df382e" },
                { "kn", "0c9de3be1ef6d0a4e2e6c6d022a2d902388fa1edc28e03b48834aaa11b8214aca03eab4b99ce6fd81810efc8c7d3355695947317aa8073a2aa713b918900d896" },
                { "ko", "2cc4f1e1fe449ea2e5b550138d425b70480a030af02adea71b17e458f5938c8c0b5c8f5cc1aee86d198f6f1028549bb05ec2cfe932d96b8a9c42d9e9f23e9200" },
                { "lij", "d4455ca567e451e4216888f6f8c0ea4bd20ce257e1e812a6ae6929cb8f1f9bc7fa8f6078727679de38c9dbf9cd217cfeba26ddfde5f63d55942b7e38e1a7fb28" },
                { "lt", "d028e03a7cee19a5a295eee6a132829cab3a2643ed9684f907662b86ccb8a25edbf3f464ba58d940393f1c3e25b396b5d46771b9615bde7fa4ada01b06a22aba" },
                { "lv", "5e94091377aac14981073f992cfe7dfb00fc655a2872605a28c714c2a700f8a2c3663015c750896e6d68875c59c24e10ba7308a7eb7953df8289d36b9417aef9" },
                { "mk", "07b62011bfe905657173fdc2e0b4001949132daee4a837197c872b8ef24d4bf75c3f3331697487e76ea2878a5d2a4d382d4e59423f053feaa7ef90d17eda9b12" },
                { "mr", "2ec7f6a534b30ebc858d708f46e192b91ef9caac4ecba166fbb0faad8070f84709381e28bfd9b80d39a200cc9b944e87c456d24e7e769fd81adce4e8763b5daf" },
                { "ms", "a442dad54bd7f74535b08dcfed65c9a117b0d7ca68aa8a9a0cc12f6d2e89431df96201aeda4b47449ba52c28c518c717d6faaaba6eba91fad10c5a51bdbd187d" },
                { "my", "9dd93349404d9d381e45791e8350fd4d11023ee3b52e5cee8266f77d38d8ca184e8e6ccf69c60310085584181ec39d317bf7e42e639b02c8f496183a90c72f65" },
                { "nb-NO", "cacf93bb241333ce54144d4667013f2fd8c88bae73cc59d1f73ed2853a533905df3e56f66121984216425d578900cf1fce566a8917a6fed319d59fd565d51674" },
                { "ne-NP", "9697b95225556652475c199a8a9229c6c6c73cfd3c217605933d34b1e7feae42926533ad008546d272e1eb5b7700a515655e3516bb4ae1f62452402807d245c1" },
                { "nl", "885453cd0106bac6dcfd53ec994621ce8ff3799aaad008cae94ab1033980e5972ff6b4c907940582b4e7e242ff938894a6d82c60a5e250afe9f2ea231303047a" },
                { "nn-NO", "ef7bcb937abd28b3a45f8253b49f21e42c8c3444d290c626e919440d7463860d06feb8b41312597c0139e4e878b8a06d7c014ac6769d55f5677d3f8df6bc4b18" },
                { "oc", "45777bedd9cdd80e5be4760b77f9ff8821e0bb943c2028c89f3fea509c8da54c74151320021083c6d711ac025be4d9e8c72e71a0afbf7cdafce762385f4f93f2" },
                { "pa-IN", "1a5b305a3484514cca3a6a26ef7ed4ab9307ee86f81e81eb8d6ead03c0b4aa1e815030f94cc794ce4ca2069ea7fe397fe8fde1ef02ffc01ff69e838cff01004a" },
                { "pl", "8325f298c82c18efefd52b591163d81c6048cfdff9cfda13d055d595aeeebd0e04c2274c114356b92f0d775676a0d349b9a2eef4d738986393a5e7ffbc0494c3" },
                { "pt-BR", "4bedf1225e0d00e3efadf36771ba8fc0ad90a7a41ddbaaa19357617aec0f3a5c9b417cfb62f3df747311b8e848d99d5829d2efe2a62733cccfdfdbc3c813a97a" },
                { "pt-PT", "411216eddb203c566eeedc7ef753600d4e9e4e6ce7036846564cc549a20779bbdcebdb58b374eba0830f9b0d9cdaca421c53b89b589e219f70c2ae7f06fc22b3" },
                { "rm", "044c3108a7f382d8d95a518b8c0b05c1a7ef3433ae846f1b8998a11514663978344ad7d7e14874a734268334b54e4675d9e026512b14451d2f74637e93140c4e" },
                { "ro", "ef8d64ea8b13df712407cc88ddfcd5ae57a9f4c3fb315fbd11ccda77f9948440805fdff7ca9d3e351ed7618c57d4700190a9b7e3ca033ab6c7cacc0f23e5efb3" },
                { "ru", "8c2ce084b7832508a99ab72b1801535932dd4a243f07b822adc6c416bac8541daa041d936ee821a2e35c6c011daba2ac33a76ee98d21e9054f1b31dabcf30eb4" },
                { "sat", "d3e207e81e8b97bb9dc982042a168be8010c76ae381248dde4ba1aceac8b256316bfe709f51f70f4edf7af0b6e68f6ec52dd7ce0a292290257a74f6bf18cc91f" },
                { "sc", "f1bc9869cbf26977f7b2eb60a800469df273f272123e3872d1016ef38d2e9436f14633945c3a827b3c7b56af49d10b32ada22bc2714f47b27d424b47b35b4961" },
                { "sco", "5600baf61eddaf2c25a40a178084e89f6e1096515196982f8939e9a02bdc07856ed2cd650d4d34d611ed8a2a3fda8cde27487ec08cdbabfaf2beeeebb8c5e5ca" },
                { "si", "a9a23d1e16b297a6c0abce472f5626af17dbcaef20483507336cf13c3df19bf5e9eb5e689b93c4558ff5b8659ea2d5365310e09e814d5ec302dff63a55a73caa" },
                { "sk", "f7c15ca9feb93a248a896ad25b61d3472ba29e4d3c5a65f59222e3218c8c3dcdbdb477f382d59bdd26b94086922d02862850859ddeb8d120beeaf700f33317a0" },
                { "skr", "e028af3f213cd168909aa4f8a711b7d4c464eefb3b601a57f9a999c378f32b77f3dc7e463a898e6856d3a599ca9e3b8d766a8cc1c01f2e27061b1e023478c1c0" },
                { "sl", "a5d5916a73e945e03484c9207633dda88d53f7aafb012dca62ed234ba2b1f178b892c9488f571aeffa467b685a83f4b0debe58f31f52c35f7881b6035c539a5b" },
                { "son", "1f197aeb011c4eb33326f52b4edbc5a8e4012bf2a61239d3cba0b16d8aa77162eb4ed56d5adcbe272e0ee338c20a864037f8014e3de13ac363dc9c1192b62eaf" },
                { "sq", "e3798f8c7912208db01ed49a04b40ae213ddb249e9e70adecfd214aa312790f9711d3bd311ff116f3948712a460f84fb213c4ad4758dc73ae730959a130c5b04" },
                { "sr", "f30ac8d0b4d43ee014dc584d2f1065bf3ca6f2f02a2ccd7fee96367a79dada2fe847b10566d5b23901b9aa3c9c3b1cb39e883c2f445d9a8a43eb4a529eb45c9a" },
                { "sv-SE", "8d181ea8bc9b0ec8dae89a93535f69a80f868c7a1a40ea651478f6ba8faba2f7e8229de519ae245431ffaef02c4e9a3fd69bd58bf4b3b46ad0d82f67fa6c92d5" },
                { "szl", "6cb7165fdd0c8c04e287ee3ae8c50b178a43baf5ff163ffa3af82ed39d49fb49e57f8807de373f64f5c4ca21bf0bb578b937d43e4aa32a4db7c4578b3d168384" },
                { "ta", "fc47782931f97210d4666977ade5a94e420624c69d3f2c0fa2bef59423ab0c56d7ca465d4798c47b5b71357e51d99250ba9076eb1f7504cb9e30ed29610cd49b" },
                { "te", "46f16e0c081a0659c44eb67f7475c81ae554b0689e2f85746c0d0416e534fb6904281b0f37c6fd4f2a21f144ebabbe46cfe67dec9f7865e6601e721b9ed690d4" },
                { "tg", "245fdb01112f7445f0fcfa04419b813ba3dffd72f63c4a52eec7e1bd28177a8e299ea0243055fe4b23d5df2f299f21d0ff4b2c9f42cdc4bd370b0b8c9c114311" },
                { "th", "f01396f5441ac8ed5c7b11b0f499b0d7804cff81e60d09d8adc9627d207eced535f7403dd537da665db76e8a1842ae158aaf5f9805bb2c83627ae869531f3ca4" },
                { "tl", "ffc3b0db34c4414fe84a04fdcdd44a4fcf289a299426be6c6853ae0d68a963bc3157ce5023df7962a1ea567eb22ef2e36301e9e77fddae0d76a1a2b018708c16" },
                { "tr", "a269a458378a408683e4bcb618f022c1d37bef8e1582e2961961181bb8895b5c6fb511b154645b9dba5129c59e146eaad72dd1924e4ee56deb8412d449fe9b00" },
                { "trs", "62d9f28117a8b8521fc980f0e1140d476814804fd68b5f530f41ff1a79c98110b04b78625b3bfd9e97a27f6a9420e102288816865c8b85fe037a2bace6195c03" },
                { "uk", "bb78d292e95ea45ef562d53e4b3e6680c142cfde1f017199ef97342ef1fcf17ceb2153cb40a87935e9810b53e6e8f000410ce4f3a743f10a71694aa1869814ba" },
                { "ur", "5e9d3b96b82481a5b0fdeac71a0c0847a080bd8b5f1d503da009be06f2f8087dfca82310a4584271addee5e00513f96c363de1678b47ebb12c3b05ee0524d3be" },
                { "uz", "9ffd784be6dca3b3bf8452757a8df949b337ebc808a1c580bfcf1fe87988ac89625fc0f5b0546643779bc6aa0bae436cf5871e1b2921238e9bb1dde93689cd7a" },
                { "vi", "17786b9f68db7c56321a7f4519fe644b7f852a9f2c3078289963807d4d78f56b3b003f6c41676d004e54b8b5b82a085417191c87ba1894a5e31c0dde05f4c55d" },
                { "xh", "4770c69e9cdef164668d12e15379b8916e9cdf0be97ae711174d20ff96a5bd04a4b0ae4f1aa0b5b268788420695580219424d5315cdb83372301d734ae22c71c" },
                { "zh-CN", "c93003a7f584593e0a98dd33152195088f9cddf5f3f223322690a7426d03706478a1f94ac2d5e054a23bd08a486798634fb5992c972ef40d000d978abcde4078" },
                { "zh-TW", "bca552719003cef1cbec532f4378366b30baf4175470f542eebf21206b75887cb6782c997791c87234b13ea48a021d7edde9f6c613aaf917d8c71cb39402debc" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
