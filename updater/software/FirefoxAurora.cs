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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "124.0b4";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b4/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "15cf996693050c050bfbe24653af1e1b0f6274a19f5a6a40dd4ee66978b406ce217c4b3ab51b5421fc286993099d14e73cb0a02174b46b5aeb83d3362535f14e" },
                { "af", "32fdabe7d1995ed3c404257b6472412336e9c193ec25dbeca07c0ea8b17f85af12a137f8d0a06f7b90ce0a6ac7acb228b77b9d7c443e50187975f2cb9fe817f4" },
                { "an", "d3b1d1b95899028c467ce27ade3f285a6ba64228787627e2def308e68a0f4771130d50d0ce5217bdfc57819e8ed9d80f464f97dd8e27f7d093d32e11e6c6c1ee" },
                { "ar", "413f7598558c66e75649bdb18ba3d0403591c67673a683b4cc32c08415c7af7662fe02d1dd6621580ee9cfd12a9f9003358dff2cbe32024a42f757c8663e7502" },
                { "ast", "8afe148eaf14cd9818c15159858fe02989943733e5c653f2b886e12f4f0514292e26928b58ad39cfa8918f7a630693c3dd97c141484533a6298acdec4e3be589" },
                { "az", "8e1f42872005ac1183ce6b6d9203444df523be9acff08b67d99735c3c7e2debdf275c0cf2f04b36304ff0c1c590d2e11f4df97c47919ae446deded00771eea14" },
                { "be", "289d23cee9f67f5ee7956e9c167307328187bbd2161c0902e8ae0531b0e35f69380f5e5a56885ab884283c0f5e9acf41b676a474e12486a6a03685f014009c84" },
                { "bg", "2ad0d872aec67ffc221aed744a42011d18613d42a937eef8793a3c6f58e7260c32ef2305acc7389df92fe96478f4f055837b1d8045ab88ff189a872afcf68af8" },
                { "bn", "a0fb8215e36330e263758de18bfb877d9e5025aa92b3ce971135062eaedf725883744912218b1eebda947039c590eae9b994e7a32342de125f3a30c8f10e74e5" },
                { "br", "2380a8945f34b9533ab0e1ec7721e814234f12e3948d6799fb825a95b5192617d7c43451880a002933d7242c125a2f80e77dceeedba9b6f59b84022a2d5f4994" },
                { "bs", "1e0d7eb4bad68bc8f86652ec4bc9b35487b0b233c59143fe22f0317d6fd3a64f7d15b422f164b32462074530f6da9d97936c4e924be280691855a7c8d569500b" },
                { "ca", "742f3d730c1f04c269d28937ecca506e7ab03fa3bff60cc73c03c997fd915daf967b6f86d1f32add8f4c0664d3241d6c3dff2252464e2cd0f30e9f022f2af9b7" },
                { "cak", "c8ce517887d0d7d2705a14f39e9b2d4fe9d5d3efcc1b0bf45d478a6da8065da5f5457305c35989b1094bb19e20c30683c3466d2b4a33fd53f32da23891a267f3" },
                { "cs", "a814387a4ecc0d78671b19bd28e4e7555fb3e4b2ab665b32c57ad14b9f1b53993da52eea9557ea546e9cb0c39f90742a89e7c7e73ce433c2a8f4659bd20a30f4" },
                { "cy", "d3ee664c14191371954fa0483173f28921e7ab7433f4559f2e020c395442030e06ea76f5d1e89bc4b6a15d9fa22998244e507f869a32e2edde0ab9bd29c4dbff" },
                { "da", "e014d64f472f2a0dd12858cf8f7278aa9531ba2d5787b84937fdb49f6cd21d5e0181fd5a0db83044b033ca2b28968deb43ea951714e060145029c9e0d2e3537a" },
                { "de", "ef1c299ba1e27efb826495538cc470f3bd5d6006f2158c8959880bc945a22abf09bbfd2e167839808bde2f614e5508d28fccad1478a5484f6c06705919bbb3ad" },
                { "dsb", "213274666ce8dc85c7c06764bbdd5242d5d16c3aeb9ed726370145e690925a7476998f8bd5454b4dd9a0aa7084129a56c8b133389396877e3255b4fbd9e973af" },
                { "el", "f7af03f23213a3d19df8ac7b7cb700ebf5a1116d538d47c780a42738e288f512ed7fca56f1f78495f380477779579c91328292077757fd2aede14e9ee1a0a1c3" },
                { "en-CA", "d885d1dccfa89c3955b364ec82d5052b21c8d85234aa4e5d85974f39316c8cbea2197287c56edc943bd010bede22c28299c148bc9bc186dd2876d542cd8b34a5" },
                { "en-GB", "a8b61cda379fd76b42f1aabef35af6aa315b0b0f06398f93d5515b94da72dc2811b5c2c68d8bccf92715da0b25823b5ae956e76655c69179fa5488ae59689c00" },
                { "en-US", "ff19863f4ed5c813f0e9473700f5b40bc9b62d806aabd5e0d6538b7277b87e14e75d14ac4f7ba3da9eca65130298e1aa7b15963593fed7f50fd9b9e29c84e8d2" },
                { "eo", "33d8f9f65e901efb4655d610d475f7c64f5af7873126d371340269e27820673c1ff3b98f4e2138e3a922688a768600b553c2ee86ec497e4ebe934c4fc8c9415c" },
                { "es-AR", "bd1574e1791358012bbdc906a8d917f0c90b4117559bf7633aa370bceaf16a5f4a489a58bc4c554f821debb9cb3609c36ca337507857a27c314af0131ca695cc" },
                { "es-CL", "32032d85d6ab5d03cca9a5e5f2c55b115a8a41af14d9744ceab907e34576575832c633f3252d741789bbe3adf53cdab358d082d1c711d5e58ad8cba06a1c4b26" },
                { "es-ES", "e39862244317dba8bcf4de810d1b5b57857ac95f4570ccedc0544f8fd25d7499303eb5f79339f4c9af8d68d7511bffccc5e8ba0783e1e6cfb03e79970bcc491a" },
                { "es-MX", "42ab10c7f65de83e2314ba4f2feac9a9be49d39229cb15ab43756e6ac3753e95168bce29b8c5fedb7d7007226d506e7d886fba6fad612fa30644f835ef114137" },
                { "et", "a1cb33279ab365e420c963c377cc2fccdffbe8009803303045e9299edbe0ee3f847eb8c127b528ba6dfd183e5a99564e1945ee4ff3b56188bfa7d21d75782ab3" },
                { "eu", "259ff503127bfdddd34f26aee9ce8a093fd92050ee91bc697c6e784177d08bc8de302b8352ff75c16816670b857acc972f57a8b7c57ebd93e7463f61c2ec20a3" },
                { "fa", "42072634e15660d8eb4aa13ade1921b5330862de42180e517a8a7df4eee51dc6f73ca223c35836d6df51edeee245ab4538bab5bb6e536e6224e72bbac91e3883" },
                { "ff", "f67fb78ba3cd2d13699f5cc79db68a968170f04e5b78523ab463157cb1f8e6ab09edd971134a4a667e63f87cd62755d0ea9cec4f010d02fab14ef1c44b6c96a2" },
                { "fi", "a6731298cdec2d01272253ba8a8b6b12812aa5506e7953fc0818d16837a7fcf1e8605149beb36092327ce8f79e8b02f714680e6e9eda187e7a9bfad04f0a7791" },
                { "fr", "bdbe6f804a1d0f50ad3f045fb84df6d2b312a252f7bc1e9b4c6d4adac0f7883eb640c4315a6004f381e3a0217649183659829d0c81e78790d1b2eecca2b63e45" },
                { "fur", "219b8d026728954b8342774b3b6f2c615a09ee40c7896c01ad72a3e897980885cc86555e92121098d5ac65d715675d4c727004e67f968238ddbabe2b8093c5dd" },
                { "fy-NL", "be17937990370ab297646a69116b5c1c655923e00ea558e58099b7973ba997ec2a874648f8e052ec72030b5feeac10a4915c4eaa4f5a2c658bb32613af6e0cce" },
                { "ga-IE", "ea0ad9d3552bfbee1f8670604a3d00a111eef2dd7a2ff2a4ce95454a51b0a2186786da4593a8e35759d0518aac03f72ec4562cb0973c65d5446b027b19eca842" },
                { "gd", "75ef030887389a768e0f2fdb332cc16521488fda1e766cb9b085eeb10e997305b97924db938069c121dc526815658971791cd3c4624f5d5de5d04a8904b7ff8f" },
                { "gl", "1c56f40b3bad3f992f410db82f4b3d78d0ec98972837a423b86b1bf8c45da66769ef6e1d86958bfa6e61845041d15e24fa0f5e0368d6e0e5442d79cf750c827c" },
                { "gn", "7867ba719d74910880d0d5f6c6b0ce0a2f6fbaf1f969e65cd9dd897153345cf0087a8557401e31cf89b85cf1ac3312c422b08e4e5a778e2b89eef6024bba13d2" },
                { "gu-IN", "5299937654c59deba3040a2a622c6afb78cb4b57b8e9a7ff655a16416120c1febb574dad5b13e763b86b14d57666a40aa14d30e97458dde4d4d76376e406f269" },
                { "he", "ef4f43a02e8c6d3bf5b1dd32d26b32d428b0cb2d8f52b73ec2d88a339f2af934c54c2842608bad631c3d7d9706c2d1b0bf1edadd5ef20fe3f6d3610e7e472dc5" },
                { "hi-IN", "b9bcf9aa7ac1c27c20a0733d41a0f39c068012ee69ba87c2ca299c4b05ea65f054d3b0b7badc7bff688c2c995765f92699f74601b0c91c1bd0558528dc5e518a" },
                { "hr", "35e597fa7fbe6dfea72d52ea5a49b8b95cc2f0dfee80b1f59b0f97ac7b0322372ebbd54e31624bd06bf839ccceb02f7d46410c27bfb3d5e76296f56d251d59b6" },
                { "hsb", "0e4496013c477f60b20e34c540ed38b6b86fef23d5d5f1b49bb0539d7fd713bfa70ffdcb4c65ed063581a019c4850a1adfb31b3702086981b64a16555d9110d0" },
                { "hu", "665db4716c9394eec186e1b26b8928c2475a746896e9f7c75db79b396f3e25fcacd3e37e47b1365c141c4e4f712684429afa3c3bbb3a72d8bd26c2ad3b777098" },
                { "hy-AM", "9616d3e83dc4a92e98b298f74efbd00fad0064770711cf9b6bfb2c138983a6266b37d165bf47aa3438350c51dda75d41fa7df7e9c6b4982ed6768b50da6310f7" },
                { "ia", "99dd7b40a3bb7213345e000acc29372f8c2ac57387746c87569546a5d6f0370fee33d6f2c9c771d91b4b172d92dad19424dabf385a14ba7705155a17fc7c1c00" },
                { "id", "6dacbce441a8b1c6e6f49e740e1e6d8170884a0dde6dccbbeff23e87fb0bedb4562255ede1e6715a059ad47b461c692c44dc56e633b2d734d26554a362e781b9" },
                { "is", "d2579c980074ae956276311cb9c11b161fea4647957737f79a3467d4f71d77a7cd17f1eacd676cfd702743fe3736776c985e781af582cf1b1f5dbe6727a97377" },
                { "it", "b3553eb3994578092f09eacdb1d50474287367a1e86d027d03f05c60c57f0346699ae12ea7227f3dc6c304694a5fbb3404c15fb983cdea7dd31694452ffda6c7" },
                { "ja", "e0ebd1dc716da2b6a1c322c40948f6e6e00e40a866c15a95a6a756b804005f707fd2d4a69a59de021a517c162c638f9ddc067e94ba57332978ea3344f1f97d0c" },
                { "ka", "8ffec9da1223d75095a65613fb7ab8b60352bed32587912c2657f866953d6ae50932e762e9d59ee524ec9036b8f251421ec646e49f55cae10cb3055ff40a366d" },
                { "kab", "e2e5498270318bb894b1a78e502e907a5dcdff2a99bd1630e54e3e6e5e63bbd014a8d42c8692114da4d974f812e27b0d1baefb06888b3a76a85b81778ee156cd" },
                { "kk", "1c58d044020e37a6c129a3345dbc7c1d30dc5f25da8f163c4489d86950ffab0cd31d0421e17d2954f54b1ec0db050f15314e443fbb7c327f543456a3a76b8952" },
                { "km", "c6bf327f45f22b2a3d7c71a3c856013cb1b51a7c532819dcf836cd6e41afd7e32445fd59721aa6064343d45832a6e4e1c580c9e7a5546891a890f4b28c0b58bf" },
                { "kn", "23bbad4963b281f73195f071e688141092930356368598f45325576f0db253849fad18611587dc0520113886331ada598c69775f6faff88a1707f74c7a0b05b7" },
                { "ko", "20e5baee35aa4e6461a1193c3d9bde7b29663fbcd0872c1fce56de058ddef2eb10d529593a52a413cc09cfd5ec1814ec92078003da4277ce660b0df06855eb68" },
                { "lij", "6e66d6512a7ecd2fab073330739ad38f2946983f53d9897dd8374bf2c0f0ce2d80f60f06de239dca8cbb790cfd772e5aadce46574c856b2a047ced39e251ae39" },
                { "lt", "e4eab34d09b59755e44c39535f4cfd3bad1ef6c6f59acfc68b54c35ceeb2d602d523847dddd8916eb00cdfd6d1088ef1b0f90dfecfc5b41478982985004ca68d" },
                { "lv", "8c24359dc94a1e1965b9b2c58f57c4d1e4ac29565798f9231966fa31159d6f35e4225652b208084aeefb6f3e5d5aa491eecce4f514e02613ca7a956a35a256b0" },
                { "mk", "e70944cf45d570a2179473642afbad72d95f605da8a3ada803a8f8f7014962703652ebf1884af70cdddd2b324e85cd79fecb70027889653b640437ddbce0c5ad" },
                { "mr", "77e835db495f0f89624dc12993982a127e074484c9125215112584edccbe0a06722ce59ea6148c2634fbeff9e2014263a2927e8ff9ce1d060304af758815606f" },
                { "ms", "acdadb1e1123651dec4ea094eed9986eb7f84f4dfe7c7158044e952695dd6eef4913e3d68c80d9c3ac6c731b93947375d94c77bbe08e2f113b5cd1b4b455e5c9" },
                { "my", "6f5ce32a9182fe83199910646c803aabbe93aeacf3d34d452b6efbb2f4fb2c10a8528666208b345062468f8de18b184266a332fe670b3a7c28c3f15a1064b37f" },
                { "nb-NO", "af93a149d9a5eee4c34a973af0c7d08c7204d897307359af37211b661ae19857bbeb525f0e5a25d7d0902e83693e2690d41a97304dffb41562f766278855c125" },
                { "ne-NP", "7d1480ff95dfc94d894864dbb45fb113e4b0b52091b06e5760729b703c79d778eaaf4c138cfb2703ce8b15b3f9d564f2867bf266b1631674e52bb57daccbd02b" },
                { "nl", "88c4caf732c8743dab3e1e65df4d757bf33d234066db31ca521ffaaec3b78684dbbf825e46e8710100342c8da03c23b7546e7267f38d2987656425dde29ee83e" },
                { "nn-NO", "b6c31bd500ba8a608aff3c4203b3094b9e04c747e1b278894f05441749ecd99c3dd57313e8ea29d6b629d2472df1d5ecf5dcede5a5e2b255f19adaffeefc8741" },
                { "oc", "c67f3da66a1c572232ccdd5a257df6aead5f36c0ac82b2d6db65ccb4a5de8e2463736fe68bf1ca749414271fc519c8c4b7755e4423084e09c9dbc298333aca9d" },
                { "pa-IN", "db431f07e724f1e05cfd4ca1334e5bc227ff2b201be90d8cc3c881e134bb26f4a049506660529eeef6c58d272f95aee3f2543d40ba2522e0fe2bb6336e2da967" },
                { "pl", "268901589dc4209239ea5acf00746755a441ee6a024f69501397c5b0a99aa6b6db4313eaa011accf2c24eae61ac0a7ffa8955924d5804ada5c3dad74e7da62ce" },
                { "pt-BR", "9d643e606a5d9af3362897e19b98164a7d6849bef8b87ae3a35c772eb08958314ae501c5f4e2bb8a975798e36845321b81f6b00fdd8c2e6db46fab6f02eec97b" },
                { "pt-PT", "bedeeece5158f11e1e91bc9e08e64fbec430bc441d44dc063cc71775eed9e09683ea4318c9a6a8c82397b78773179805f3b11262f5d33b8faca1007dd04eb65e" },
                { "rm", "3ad0b299996f61269abbfffc1aac6666114863845a97794c4e159b16b813f2de434418d8fa5c15361d7e8dc3b9a87620c59d49a41e016905a5733abb7f0f4a03" },
                { "ro", "328833cd5f911b0e988db4bf1bbdd62a82443423163ab29213e13fd44be69522d3f2ed9f53e40863543b82ca7b81ca72bac86e605d499ddf38342b5391387852" },
                { "ru", "70e5ec6cb1ff48037c2eb2bf81058996c48e655cb7448c0dd1a1c693ff81aaf71d6154d2c23d711243eb13ef2766911fd5c1f5ba2668b34773cfa49013ae4de0" },
                { "sat", "133cdcf7edf3e87a6151802ea4d4f03749271fba1d7917050c20108470fbb3d8b7260e43473d563160299e28709f2e5f0f602274a009b6a7d8cceb0bd6af6629" },
                { "sc", "33cbcf06981f0813792e1c54f6cbb74fca8ed175c0d81310220cc10b060b7fc7c8ae231cc83e3ce48faaf4dd2f27a673d9a482b4a7ea9be0ca62d00d57820953" },
                { "sco", "35837e05683ad43aa437dd5f97251f1763c26a607ec5cf5723b4e6225ec94f90ea261654224ff2e849bf52f3d3abaa8eface23a250185696debeff7aa31d3f32" },
                { "si", "0bc19138e0b176d799939f59ed83bc915ed8a0f95556f5eaa50afcafac4c95ca1d198bb28ed3f878f29ca6567f538b49837c041aab91feb977128c08771caf1f" },
                { "sk", "c3a08f679891a41b02d74ad7b990da46ab236b4808115ead2e8524886c4098784c1ab8f3ca62acdece1d6f48e25669ee3195d2c1e02cafe35594b2992954f567" },
                { "sl", "387f5be8bbea3d4ae88f453da694c4bbe80256d25c90dc1de98b6b4337e4bffd41501d07bdf8e83938e8fed353702a95b6781f58ec453013020d287688fe77e7" },
                { "son", "7f9f0a59c221c332f9b9782df6ec5fa64da3356259dca0c82b566867a5051053a971d0a762b26b16a0c44856126abc94bab552a6be1afa20086e2ba86333cbc5" },
                { "sq", "1526e2b39d38761a469463e2fe5ff9df60306db022614b3684391a33424b37fbe6fda77b93762a5739ab1839068c7d2b51dedda231e87063ffc04216f94d99a7" },
                { "sr", "a219baacb12a34e40d866b83a51eb90e05a9c750dd50f5e25c4ab5b6ec50d47877a41b49599898e82ab42c0ced135b460d74c23f64559ecd33884ed662b6b715" },
                { "sv-SE", "aafe603b9d13107c3abac04810941731a4c9150817cdeac9b8f7eb4d01bcb6caa4f6c1388fae149fc8c073f95b62c977e239092bafa9f57aca7384bafe358368" },
                { "szl", "6e8d05cd2ee831e566e3511b1bab7ad7e345af4f8f5f71950609e650280fd869712c3a0dc9ea01c40da403dcb4531b4d1e39cfe4ddf173ee81094db0a4cf29f8" },
                { "ta", "338152e5fa9ae344e4bd47ba1e46239ee9fd3bb7989b948c553bb93d9f97dfa2b7a5167fed51a6ec9b5a21a5d074cf8119a4758c5856ab862fa9e3cf265bb41f" },
                { "te", "7ce0dd13c436381c769fdf786bda8701b2d42184e1e6198111af00ea9ab78a5f1fc966545a9b8a591826b56ae61fc8e6b743a1023173f31f1ac22138721071cb" },
                { "tg", "af6887840a15cff178822b0daa53431da91ce54212ede7bd3d187a2540615bd226570dbd15ed5d9c94e6326a4f809ac66e433df0884a70c2b026b1c944d7acbb" },
                { "th", "f30632b9bc041749001d12d22e1860c1518eddc86a5234f963899641f934fe315df78e5886e4a6aeb51ce4f8e2dc6b55e212a07230b179b11215e6db1af2f70b" },
                { "tl", "9292f94a6a5e24b42d3116dc4d7bc01c35ef7e6c2c240dc1cdb3d70a3e50512b0a7651965356921b673f72bb251d5e6bf87915475d253f47f06fcba2bc29dd70" },
                { "tr", "53fbe8948949539654f0cad7a82a5b1b72327453df1f950ee7de3a91fdd1ea2ecae6583a6e646d17d2d9a304fdcb2340a60a0a6a77a3de4a91380d2be4edc9a9" },
                { "trs", "2225bd270fba6cd067e781f0fa34964d118c87183a9c4fe54084ee1e4751b2124b90d9bc2812d272ba52370296721b35d2a7593338c9e3c84e9b6fbb3030d241" },
                { "uk", "77612823c9023660424f1b7729a0bdb3a46b71fb6afa8006412a4c374f4b35e7806e578f56852724f027aef039bbdcc67b23e8275948ea16a1eaa45790a6a697" },
                { "ur", "03f771e1bf972c78f6d5e9b77d202c791590cbe8a4b608f93072c9e309202a3bb7b6b7f6462ccc41a5cb751f2d56ec0dc2bd6747b5f886da2dd37a7c665f4e4a" },
                { "uz", "99894158e74fb4c048a772656892b7fdd91037e7f6b48f23cd1ff657aa6898d1b4411cc2cbfdde3c4c82c310a036834635d6719b3a4db511d339f55dfc33d89f" },
                { "vi", "d1be4eef3ea84612965375437db839d47de00f80e6ef99c6f9cec804cbf9abd5cd603f511951095c1f5ef6add34c232c925001e4590b5b5d9957bde5e5e05b43" },
                { "xh", "c7c3fa9c255088a531979c28cc2b59f31e863178c2f9ebe3bdabfedac8d9351ca07fb051caab320310b2e28510f99cd4aa5e7e06f1f1985e23c4085371689c8e" },
                { "zh-CN", "c9936fec0f656b52cf4fab4ff20ae7ced700c022f4511c6420dbbb97f6dfda5fa494693bc1658cedc44a34f88d45a632eec7e579e75b18238b9bfa78f2eae16e" },
                { "zh-TW", "37711cce62184ee025704c8700ec6c8149b6f26627835c85bc0de5472a4903456f73a11bcba25532264ebc59651caccfaa48ea566cfb3c801800a79fb11e470e" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b4/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "05470b38434ffb9ba680b5aad231e45ed60608d4cea1fbfd91392cfb7780bbef220aa4b0be955cee09f52dbad715ba2fe3f95d181a10a1a1454d12d5281982cc" },
                { "af", "d6efa7b54da0f14ab37b931d7b3654c2e62447a500bf137a1980c95173d4e879b22cd5b9626507b777e1fd64c02424eb52c9112bab8e0d0d0695d78e2f17e28f" },
                { "an", "5608330f6cc684a0e9cab131e57b8fbb989fe66c5a6b953d585ab1cadd09680e372de8bf6953830f9b4e3c55ce781565f96b5703b147f0e2cc3db5bf145870cf" },
                { "ar", "64e8e7093054f48d5ad1b00b48a036e1764882d540d62fc28da0dc7be2f8de3caf5f0dece61d0628e1b9e37243a95beeacf90365dd1264ae85d8dc96c5bdf892" },
                { "ast", "c634be04f47f4da4ede63c030092d4324eb5f800e034356f189036252fb4d2f8a3e8e0ce5c9fae78043de78cec9ed250a59a554061a289013f787404b11e8d29" },
                { "az", "fc7b9c4031b5345a258c4d13c80032b634bd0e434c37b9d390da1575b6efc889eed069fa363dcf6fa1b8cce8231ac7c660e846a12d8f29f4824958ae11324b0b" },
                { "be", "d6f8364db71110849cf8383d102179778b73a46c0da135448ee185f51f4756cff1ecfd76cdffbd799911570835df23f30b5dc33c8e00b37f416215fee1cc2532" },
                { "bg", "fda68395ae360c0536cbd845f5d93d0aa171a873b628915749df90a988821ea583a9c435446c3dd863104d16f1b72e3f798451afd2863e42c00856f485756a7d" },
                { "bn", "c8cf6f19135bc174ae1b1040abb34022338874bf4773e75c565a16ae57ab8fc8cba8941575303a1e30c58a36d0bb9267c9f0d5808bca2b7946a0dddab175c49d" },
                { "br", "c42535b971140ab3f7136c47aac07fa2fd56d8322d0e1024b6c924921a6de974228491e25eaa6921401eb3a8a6016fa3562778b4629ea79eb4e92eda6a02eca3" },
                { "bs", "14d2e8c54bfe4a38e50f5b7cfa1f7f1400ecc29b30d14c0405e1a03a17741660856e97852d7c586c2052f2559ca85f0b28dbc4d2dcdf6f9666139d3a626d9c8d" },
                { "ca", "0a5a945832fdfe38c2549b44ffcb9591c6e46ae8910ed9490bab0ab0b94996b74295e8e1ee43a40bc8e4d8f14cff47e15d38f620f13ddb24eb46504d935ef037" },
                { "cak", "66345e05ca245c8f3391264c33b3edd39b43f5469300bc8d419dbde5918265f9ce1292ffac63addd30c07b305f42191070e860da83f6c3f48b95d5fcfd23b522" },
                { "cs", "7a1d29bd25c2b2ed145f8cbd65f2becd651108655b1857205e4ae1ba0ce98cd0842686ab2edb193fc97f53cdb3e01c8692320a4aa0a6b3ed20fb9e640807d1b2" },
                { "cy", "3cd027242ed40f44483674626c0468e91f099a44271005b46defeb039097d97aefb08ca0e811069204a7daf3eceb7dc580dc93b655470fa505d6deb4b532b920" },
                { "da", "72846c3d234d0a95ce0fa59dda4e5d99d85935dea38dc15acc6bf0c96095780ade4d0f28807786854b305abc31fdc337a07690984650d077cc1687a4a3c6f2ab" },
                { "de", "0a1a3d1a464d2f2caed40fc6f89987e0a5169532b22e64d7f3bb58032334f8f18ba500a97ee4d61ec87ce5911d3e7fdea263aeabb2831def1b1754a69e5d79d3" },
                { "dsb", "3829cee60fccfc317c596a4c97ba8ae47abc614f9f601f7f2fcc8a766820edb4d59dc1461d95574b39ed93a5c48d4a41cc40a0738260a5f2e8658cd1c54506f6" },
                { "el", "07baf437830273feae5d63f69b9ee19e962f4aced3d93fd376a127cd58d2f2e83c15db250a40e2418f6f5711e9221c9db0ec0cb240d0ff923436334fca2afe3f" },
                { "en-CA", "735a3f6d99338c2ce30678d1dd7d015bac31b3289b80c6eccb4d0fae6e17c3992d1a87d371aaaa6eafcb7a5eabda668655a4333fb9c6fab35145aaa9585176e9" },
                { "en-GB", "60d279f42b80cd054648f216ae8832bf9f0545bf19b1ffb0d9628806a0f6266a56eb515d7915089bdc16e7bd11c0249c473d1c7ce18899967e4dfb39f857678e" },
                { "en-US", "7f7e47d32e0627cd8565b1bc13c5f70b759daa44e7f43baf6c742a6d089a60339e4ee5c0dc654d3fdd94950304989978ec5117eefd72e71330b51f3f116b5949" },
                { "eo", "c58ca1948da5ffea6cb94a1fb9b304564f57fc4f6a0c324cd44ed27809b56be578be1c218bd6dadc5e41cb9d998288ed02786d86316eb69075be05db48a38efd" },
                { "es-AR", "360df9407c7d4fd4691757c5c46bddaad1c4e12ac75a4d9b113f68edff2a40a8f149cfb51c5714a3a1b07473eaa8c369bbe3b2b5b909f9efdc8d51faa10eae60" },
                { "es-CL", "1c2e457a3096aae0fa10cf5c56d927b8f3518ac5c964b79df758a03bf5dbcd9146d018fd029e2b8257065b74db03bc7de99ae9c8a95e46bdf5515bee12b873a0" },
                { "es-ES", "21026f07970be731aee556378dd5c04151442acdae208f0295e91e3f5ed6a9e08be68421b6adef9f3f96520c5a567722845553f0928933c7df47fd3f9e56a89d" },
                { "es-MX", "df9c85bf429f4fa039cf8052fc2d40e79cf60f6cae773768739fda2ab3042b8be2282352d85250afb0e5c21d9d4fa4803bf14c029793ba404914c4650a74c325" },
                { "et", "291f0ada3bcb757064ff16d043b0305b213781a58e0ffa2827ee63e595ee50cd2fb7e9d8ec3764767beb6fcdc05dd4aefbfea7bbe55d79c00d1f18fc73843427" },
                { "eu", "198e3dd3dfb076ff80fc8b6a65292166b1ae160598323586ebd453cfe096d6124914ffedb23aaaa52177a6379e88a967e87da675bf67bd67be7892d50a81ac75" },
                { "fa", "62d3c609cd246bf8d8f84ea9645ff1aa5a2e811f0ad7a6964d26e959b83ce8b71dafd2e4a7684b89a759977e033ff7a9921225734b73213dc972cb87bbc5e48a" },
                { "ff", "78aecf152bf85ee54402cbf259fee05f62e3da152b3cb9395fed98d1cc77be38e722349895542b300affb1c1a65c6f39ed655f5f26f0e4d662e06ac4d22184bf" },
                { "fi", "ba07961d98237d365b3d8eba812cae5abb61f0666fd36d379056b952205c701e474f8a99c89b3a52876f9e52aacf34e70cc83eaebfebe6beee0ec0a92bf5d386" },
                { "fr", "3ce1aba6970559faded89b5cf023cce9a72ca4f7a57a49801a07ec28c78683906a44ba685c73f13adb37ceb6fc6436f9e4fda453ee6d25639ddf99dc6fc119bb" },
                { "fur", "2dd42320490a9f4a36ce41af096e4b2b89d981af0f11a18ab973c3fe9eb4cbd8ce9b9ab6bf6109d78b475077bd4be81c97dd539e8ed547abeaefe9480e06858c" },
                { "fy-NL", "b7d4c247acaceaf74efd49f1532fc13d70e8031b078a38adddee04c27c0f910ab1fc09057c3ce455158c580699fc9e10315964895058284c01f59ce3b7e2a69f" },
                { "ga-IE", "0674c34590e2295f9b6dce56cf5859a84929906abb8591c69965ff0a1df2a42e84a1e9e87f75674c5aa55240eeb05cb44785378196b8612e21bf15da4871170f" },
                { "gd", "e9a372dccbe61110cce3456cf9e3c0ea43eb573ca5a1768c4121622d0a8bbeed9f42ed9a2465610ff02bf5dc0b499e213045ef654cae1640b530f2babc133590" },
                { "gl", "60270a6c600917a4a4806946531542b0136e98b98533617577cb9577f2a630abaf7002c8290c641f7824fd03ac22a2d6d14ae070a3c8c17d98712bb7a3d847b3" },
                { "gn", "84f8ce6267e0725d9daa1bf1dd906eaef09c91522d32faeb478338e13927914bba8a6a479e1a66c380ccd3a058f921e4877da6fc573171bb2842e496b7a41cfc" },
                { "gu-IN", "201f671d63d25badd1dbad5330b738bbc2e49facec00576e9ced456df709594625ce4710b7d2f3a6416f14c993b8aece790bea2459b57b7057382d4a3a2c19f8" },
                { "he", "38e220ce5b9256ef22a82db6abd6ceacbce7b7a68f4596bf264ca8010281e2440b90e1b7bf21d03653d0710f10bc705b2c0da8b5e5601cee1bfe1b6213c21a2e" },
                { "hi-IN", "710e10986870b864aeb3a023b1cf95f9f55f4abc1c19344b512081e009769698f1bc2a1a7fa8fae7786a34e5ebbddbc4d5c6883db5e759f9a7fad6da64bb9d40" },
                { "hr", "6e1384079fcea690430303e00338704b2b9bf59d7af825807a9e8b112897ce65ae72ffe0d7151e443deeac05b222d8a3be3b0688e1b6bb3f53cecaf76e0fa141" },
                { "hsb", "4dad66742eddbe4ac01699039bb4ae2707efb904698fa42312b5caf23d529ba7cb9928d1b9bbe66df20bd7ac819ea3053e728e0d518b17ac1b050827cf6f4459" },
                { "hu", "e609346b47a41c42aa72f6d9390bc77bc8d3ffcf552e007ca69b5a4373cc9249104e41f137884cc3e4f2dfb78aeccf437cfd0c8eb7819a80b2ef2f60834903ac" },
                { "hy-AM", "14c3aad3310fe60b1e296d14cecc9e498ce2d33fdf306274c006549297b52c0c71963fb6a9d6852b362380a4aef6cf9b6cf6b469f767b30a9bfd8f9e4b1e48fc" },
                { "ia", "204c8b97d7f26a169b4505bce7fc7503d0cd9b01098d870fe64994dacbefa226cc80cc5bc24f39f8e2f63bbd2c850451bfcbb1b84930a25ba012effe91c7a4ee" },
                { "id", "62eb1b4f89cc8536a2c032940fc9240b08d2d2f938fcbcac4bdfca4d808473ef2f1cb24452b242d13bd6092493e093200516ef7d2975e1bd8d06e90e84e030fa" },
                { "is", "48092a78b00f3496a7c80b09a45f7de69af75d34cd9916f081b4577970d2cdaca765e7801958312b25fbedbfbe5626b8a856286f743a26cb478430647c75c1ff" },
                { "it", "3fa338a3c3f4bcefccc434d0df84a53aa4cccff1e666a803ba6c468869bd6708b959f99b273c8a142a70e23e9079981fafc254c3ac8aeca871ae69b672d46c25" },
                { "ja", "e661a389a7808159770d33ae645e8292623a8172622c6f18c848a0c70a047fa95cb38c544f77605627ca04a010efc8ddee8c309fcdc13fa5607726138eddc17b" },
                { "ka", "40ccd3640b77568eb2f1b1fefd9d0f1798e587629f3576893b50bcbc4024d7f1a26fc7bbf550e3544a679cc9546c4dce7f7038b57ccd778e02eefb3ccd0bb50b" },
                { "kab", "6c1c34cc19b80712686f63ea0cd386aa87ac3c8fae6fcd80308bd370ed15bb70607cceaf7dd865fbc863648634d36399c12b6e91a29887e6fe1381fc8dba0432" },
                { "kk", "97ca09af2baa71a5752adffe766c632efd160992dd5f3d6714d382fc792059129f65d1abd48e4989bfe7b0e5a7bbc1f8e5ef9d0805604314987d2d4e4b3592a5" },
                { "km", "63915d12c346c1a7e6bbbe6f6df850cf7dbae0e16c50ff298c16727873695029878fc36ad714e5f048df72489d82cc7c25b60dd8a2819bccfba63b0389c8b767" },
                { "kn", "027da45b41ed26bb7e8cab4a997b3c76d297e1e11e4a5f9cd7cba58e5e27949ac0164c210e1e06143283ad988529601815429b12f1a59fb009061a9d8e9fda6f" },
                { "ko", "5c589bdf9c00ceb2ee0b42ca0adacdefdf5395a5f3d272c2711afe6aa1a06f56b4a4db8c89bfb49ba645600810ab6e43c34da30ef184ebc8c0282d24972bab5a" },
                { "lij", "ac673ad75e9e1ac9c4a9c55be1d046a391d41c9edd0a908a21d91692d32207aed79cc4d543f5cabb4efef22ce69dcad1e9153c3c704dec24bdb315c41ca99007" },
                { "lt", "18714e8e3d070cda2e7b2c52b95eea538801de34ad04c13f15203d0a237c110acb21dab8304096b240fa9dcad8d8d009858fe6e5c52aa3aae4b4415c2688b2b6" },
                { "lv", "49fdad058d5449c7b131fcad116398eff26cbb64421afabde146aa3fbdc733a168a11267d554f11edc8a0f7b46bc4800f0477adf2801633c3b2c88a6a8903eb7" },
                { "mk", "2506b1d2718235d43d8892431645ad2063f899a5787db847dc18c848464156e8e50e8eaaee3fdf929d488c3730c0807c56112fd73fb57dc5f869b63c04a9343a" },
                { "mr", "ab32e813f04981b0dfcd185c242069f0e0da9c25d65662f45bb16fb48343df1cc5b3c99796fbf69ecc77525d2ba7813edd7bc882c594f3321ff30680b8c3575d" },
                { "ms", "7b3a0bc551610539cd5d9c0aa16ed7e06a5060497d7bcd5ad09c875b356130bc9516625a29a06e3f2691bdb69f4e345c4c91a9e275b37c1da21e84861e1d887c" },
                { "my", "a3da1b1f50688f4f26cfd9a8c51d3af5e6f7d40f74011c7c95dc50c232605f6ae13f2789359b562406277093508d5f40db5cfc88b15554b7baef4192382cd819" },
                { "nb-NO", "93a334e568d415f1866fb44ae612fdf191f10e7510b63243e3f7b2c43b0276f1817a5fe57413663a34b79dc932dab48700842436f64f334e2fc344a38c8f8faf" },
                { "ne-NP", "d1932ea90b3c7025595b691478911eb3cd0840ef45ce7f3e4060a354be301d7cb7ebb28f6141b92b6404b325a1373dbc1a5b9cd38e9640a0e809c2977492a502" },
                { "nl", "26cdd0de8c1b37e9a8622aa0db8d14b345e1c2e464cbd07b20f63eb620a6d4b4ed8a8f16353a9a12b0db208f901a148d1059c1310fd6a7aa3a5d4f0317de87db" },
                { "nn-NO", "dc91bd573442de7b58cbb2b24ee3b6605b5519ced26099b731f3202fbe8d10accc300d113ab019ac32b008179ba27eccd5ca43f59b21e93791de7ca485ec594f" },
                { "oc", "1553af154094e851f3f6d7bab926e52750187403854464318a97bb933903448feb89ad23b40f411c8696bf667a4d83354bd5fb73b29c0493bb77876fd802f4a4" },
                { "pa-IN", "273aeb0a97a698af7c94b5010b9bc1f499544f3900beeddd7f93f08b26068fed738d7487530e7142206880d672051b32c6bb5af3a21ed76506288fb16daa9b4f" },
                { "pl", "c595d777faa80d46c537f798653e6794269d7240ba83bcfa601bdd2268a62376666299a3df345039553d5a44f03fd2928f818362d54df18c4131e4bba25d0e1e" },
                { "pt-BR", "00bb46edceb79e33b0b638c7dd14d8cf53bd94df614fe0ea4da8e6a041b7a2113314a648ed2aae226f631db82bc0728fa7ca097d759c6c3b772f51c69c9e96e2" },
                { "pt-PT", "1c5d873418974ea71da92ed528a3055763ca3bed34436d3b4355046426683666042fd09bbd3dc739751f2c2c9ab51dbae8b2b2f8bced73f980c545633e1d4068" },
                { "rm", "761ff87c8cb9a880e5b3fa5fa1e88ebf0aacb5f3b4c3b7ddcad85bf2810b622768600b99ed225e65035b58066039a5a6f2620dff3dea7b226f3cfff2285b75d3" },
                { "ro", "c14066d26ccad681065fd3aa2a0f2d9de7fe5bfdda0944d3b7e144ee745e7ae11dc94310be540a0e0655c4c5d36ec088ed62334b97c4742e1579f21877978130" },
                { "ru", "8118e137bf62ed12d566357b2b520389f552e987ce3dba8cf8cd46b710f4294cd9a6d50b67955937f4b938d09e8cfdf6bdfca3453ae0ebbf43ea190c58fc8758" },
                { "sat", "4bd9fa14b98c3c964f440606c1ab8f918aec4400c199752222350afb30de632815a5ee3e8345eafb7b00de069521424b18f316a1484caac7b890e07562fe5580" },
                { "sc", "7b514b9b1d23b49fa24691f598c2141d34f815f81d352c4463fe30fbaa8bf54d44f536554a9c9aa6591a3f27802b53fc51e98d79df2865a6c88d6d016597eb36" },
                { "sco", "e1cae4b1d5b056373e4c312972a5ae074af42680af676999ce2675db857ed32c174c188ddf8f787a010c6e67831dcd2d1aa1d9af711a136e0bfa50d8d195b1f9" },
                { "si", "942677ee3cc7238b26eaa950a05d8d24b98ab8fbd81d8b08eb4c4be3336c50d0c3c238c8d3f683379e97d24c25a6ca73aaf9377f5eba16886649514b0ce7e97b" },
                { "sk", "91ce2670ea6825f9d84311d72bd2c97a35c317f47f21ce50887885a6b5047b1914fc04c1689c517681847ab0b45bc99ded23a4196bc4ba8edcf46325bab3db50" },
                { "sl", "0940b42fd18e7be60fd74ceba20468a9f264ca1ecf1a199b50b596509a0fad7b6331ef11fca4d6025b1ab8da401e8e9600e2c67d4abc88c6d9b25e3aef8d908e" },
                { "son", "d06830c2455212e04c19c613cf48616fbf60ad6acb2338e0993ec2811a92512bf616486bf8f8e15d02aabfe660b126761e2028192861f3842fc64311ffe59d86" },
                { "sq", "e8ff5b2f7d7c4d53951b8eb599b4dcd9e48fce254d9ba82b8b41e560e2a2bd6b191e85b87af13796a77a3bbb66914d507c3bec1414c44daf5571bf3949436ed8" },
                { "sr", "2ab1769699d8e935d1ddc9ba82a61720cdbada1cae753662ee97a69878baa84586c7a767eb3ee7d417eef1de9a5489173e2de438a77ab31b82e9d9ecabc14677" },
                { "sv-SE", "abfed8229f84b90a65b1b5eaee4e390b98a660ed61a7867882e7568c408a3b6e734322afc75d407b55974bd270464df01665300fbcc246aa5fc744bed9b1e36f" },
                { "szl", "9f0d63107aea4fb65954668b3d820df451c4cb52d4a4fadedb809932cbab9491b26f9df27974ef3d714a1f69c34187ffdfecf7de0c3f877501772ca1ce38ed65" },
                { "ta", "2529efacee0910c11ca07df09fcc13e1e45ef1c1f4d76447131f381773c4d77e984a38126d3dc1c63e21471197a0389f2b6dc1946b9ba9149d4d86d6cc58eefc" },
                { "te", "19965fc9a40e888db10d0b79de1496a7b0c3498d7946de4468b6d6cfda261ac284098c9d6fef5d7be19e497a81e5b92d62e5d5e2b934c3406f14af43ef8aaf3a" },
                { "tg", "17858e3e242b380272a4f81c1386f0ebdd763ae5869a5cb5ee14330cc0d8bd0907b45ffabea2a52996f1793780e86427e678d7178859950c62b60f8ae556a95c" },
                { "th", "572a52f8304b6514fcd5232eb015fc4ca39249a10339eb1eb207d3e62ab90f0ba9b9f9a6576f0a28321e4e04941824ae9bddbd75f061ba56ccc1fc86b8829b34" },
                { "tl", "c136e60188562e5d78f12888c06ca4b32aa50d9686dca913d14b6ff8683119c27362b34684cb5d683bc9ff285e27cb4c1ad9ca30a1d6028529f3af01fed540ec" },
                { "tr", "20e725e0e0e027326486e61aac5e477e7bff0193c048481a9a3c71cf000c42501162cb1c9bdd63deab66af0f530a154b0c0cf0949e92fe5600809209876d278c" },
                { "trs", "a9d0fdc89e927ce4b11b78c267ae4a80a06df9058cfcd6378d7938487ad0c600a88f4a5a7e418317a82f1e2d0c4bf1cf5aea21bd1f7307c27e8756909bb59a97" },
                { "uk", "7b1278dcfb2b725e06be7cd10ff0835c8b98096f8d2169cac4b916145b9774b569f0579335d7d1008f8af5d2eb2b5de8405f9c48517b5c431d6227004fef2b3e" },
                { "ur", "0c5bc7dac76c1010782b50d30a243a4d90fdfbc7e46436d815b34aa0da3b96bbae580cc469c16b36c319d61144bc3f59811b34c106a0fb73bd8db142f886768b" },
                { "uz", "75481b552fc3ce8fd495bbefb64b304ea0ce70a1eeacb4cc578f1a4e2a24a959c82c97208af8c5d0dda0f4c50f1e9ecf48371b88ec22400696120997ea255121" },
                { "vi", "51132950f98975579fc436c889525fd59ec62f20c1a9f40493efa7ea102845e4dafc951af5d805582da9e46e45dee72358fe1e1d0c92ce0745035965dd6f7e52" },
                { "xh", "e2ed77543aca290ae170babee0725b8f63668e2634f1f357b8be5f3e815e6e7357c1bacc677fcd73e92296f55ff6adf71452a0dce7da598ecafd4fdd25ee30c8" },
                { "zh-CN", "f91c0dec8bf9be1c9133b07b9a4f3cce4b850c8524e23f775e09fb84f6d024c02920e593be78a04beb691768fcaac2ca4e99fc1126646e262a74390ef42b2ea3" },
                { "zh-TW", "99db67afdb692f42ce8e9b9966116a7876ff3862b69d6c7efa80f455f7adb04e4407b7d5830c1034ce24c52e575e96edd6432abd2b0f2eadb75bfe7c234a2928" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
                    // look for lines with language code and version for 32 bit
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
                    // look for line with the correct language code and version for 64 bit
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
