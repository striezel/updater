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
        private const string currentVersion = "126.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/126.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "dbf30788615f39e6e733fa0d219956c195371c5020a65f33f9db4a7e7ca5dd8cb4091b7a768872f77688cbc773c9d3a4aa556ceb9843dc2d1ccedf4f438870f5" },
                { "af", "0065ad6af5825de72c014d514d76a666f4123bf63cb01f637536a07e15b2a31ebec5af2141500a7ba7768a5a0b2ab7f135429a07d82b9ccb7a53131e088eeaa0" },
                { "an", "69e26673e47d16781c89838524da14b9a770dc070728bdda49e0c2248a3760c6a9738f7f5c2d59755f2e9b84e85f9c8dde594cdc3b9b0a40d27b278d63bc01b0" },
                { "ar", "de529501960d6ac40fe402487f6b559cb3361c3a4b98c3722cc06d1ffa4baa4dbe7811addffe615ad537ab79a12bcd701bdb1e56e26893c90b0fb1ef9ea0f476" },
                { "ast", "ee8514a45dd66445844d0c829d7d6631d16e040ccd9c0a5dfdb41cf58a28b285bdd8cd9113837f75a47e94898e920abcf684e5b4530ebc1c1783a9227e6ab0de" },
                { "az", "c762c3986d60ab321ffd3b6e286c905839b55038c86318d3436f6644f87b6ee0ef7d94bf03e9de8ed851337b6042c355c9f6f3d573b934d70834ef3f80906b52" },
                { "be", "6c58f9318353aa72887991fd4d6e9449efc5393590dc9e16a23f5788f51d4f18c5a0c51fcb809485a56688e7ce48f32966209b1f4374f1a10d97c3148e765d7d" },
                { "bg", "46133977e22758a4121d6a04a5fa97f596ba9f6214c8c2a55d817a8a870303129460eef53cbf8afc1eae898222ef09b37126ed6a3be785550ab8531752cc3ef8" },
                { "bn", "43347ba2b738ead3b4644f74f3b70da6b75c7983df1878003dce6d4ee25178ebdfc2b936032df50a0fb5d04ae866ae6015e42b34dcbf47e02458b2107883398d" },
                { "br", "7805f4a394fe78691b7d281450eebba9d14d454de29f51c00dc324d74b5bd93623726f7f667262679b908bfeb9fbd18e3008339aebc78843d614a56da50a343c" },
                { "bs", "6817c904713965a12889b3ebeeaa43f42d35df774f3546cbe6245158a91cc2d78b5e420883f7c93a7d04196e21c6bc0baae2f63bffbd6f1f095a3dcdcfabd29c" },
                { "ca", "9982a2fefe072bfe26cef574acab0a1c606a4e3e782062b71832c4014fbdc270a945faef6fe6dcc1c262c8165bf4342f10070a4a51c87e34a14a5bdd0a7751da" },
                { "cak", "43bfb6a7fb91de91b99d77f5ac129fa6d2c7940b9e2d1308e0346c1dfeb54c4ca75bb2aa34012e742070a3f347456db0b1b57c8bf14b6a4cefc7c818a4ddbe1c" },
                { "cs", "a615bf333641fc279bc0222e1b0f9b5832c34f1d4340aebaab24cdf216b92c337f61eb0dc9a9f6d3072100977f005459cd7ed36025cac86259a8949cfdf8da48" },
                { "cy", "cefae74099d9b8b6e1932a0dad1fc5ef375ea84e342dd359cd9eaa5f8a99faa5a2ef219ab1c4aea79000f5480adb04a95b0fc697f13bf9b3fb613755ddebb479" },
                { "da", "d3683b74475da612ff0708d172d7eca4924c6d095236027207a27460db8b5e5f184729462410b740edbba47283974c89effedbfb3952293655e6cee3e0e21e90" },
                { "de", "4943b6dd60353a417315bbb95fd8c0c43acd5c674db0e487e1d55956e984f19a9aa3919d6d37040a0368f321abf8f3a59bf7ae1004808d3e8939c5c9e25809d6" },
                { "dsb", "5fb136cb306022833109b81ced9062dfb9b3b7664456286a7a1dff521e91ecc5bbab74e8e39bb7de006a23bf991cc3d2ffc067aa89f935ae78b0d8715a82581d" },
                { "el", "44814636dcad6ef1388e869877fe8ee762797684ddf70459d3ec9b0e3b7f0881e1b3b0f618ad26961825a78cffaa479c2e73b1481a5de6d8f8b0fdcdaa588efe" },
                { "en-CA", "4f8c70f7e835d3ba6a8a2f8ab270eb5f2e5b55225efad4ec3313d533d2e0954edf67a0428b8b486989e2803d6da9bc8a027864122a244333fcc360524cfe0ac7" },
                { "en-GB", "1672c55f18599231d23f32f9530f01d49264693a43e76bf04b0d2f1935c74806a987124e380e6e42d98af82f61419b4840579b198a4a8583c629525a209faf3e" },
                { "en-US", "92850907801ca4e30ce5734a03afaf6886cca7735277cde3a22f843d2ddbc4e318b504480cbdfa5ab949648058ecaa32f7e41e22d0f0050351bc921df854e8d1" },
                { "eo", "3a6408e010f0c2c6287f213eeb0d2d04c6fe0acc1990aaaa6ced2e31c557fa5b36f4c1c6546c8c03956f4b2d33b07b38dce009257feb38a92fd8c98adb15e11a" },
                { "es-AR", "20bae3218466be0119646e108b24dd26ffe0e1e63062bc18bf3d7dc0167d7e2f8f18ad04f7434f73ad25ecd0ecb124e0d9fd3330a54337032d92abb57e54ac8f" },
                { "es-CL", "d104e401599644dce55f132ec9d7dc84134deaf8e23b0ed48b23e36247f3d6be0f8183d00cc31da85961093c7427ac2a256fc35da342fd79fb267df7410a5b92" },
                { "es-ES", "7453cd8940211c0176c922e4d7de244d09f12cd5b014906076a0dab6a6244143a8e2b2f88a581ad97e0662922707ac653943cfd11d542122362c21b003fd8c00" },
                { "es-MX", "6fba389e7a3c8160eff0cfac7bed037502b633998dfde5d1d1bbb23ceda3762afc220602112267d3cb1e1cb09b2fc8fd8d5fbd492601b493e1530ce090afc095" },
                { "et", "e1bca25d6c34878429d48dea4302facd9e17397d6748407826e78869c573fa458213f5899ae4a376fa45d70f3e4b66e02003267f5fc8d0c504129de0fdca6ecd" },
                { "eu", "f0a38d89948c0da6e979a34e1e95609447db71bfd8cc1840e61ae758e1702ba4613589f2eb0700c224da4f50e7799c4d8cd6cc6db29dd2db7146a943bd00ad12" },
                { "fa", "8522a5fa8e1a44471044378a023c53fc793cbb33616366094da8a02c26ec08b7007a37ec6c84a7b18924788f5485709768d1b378131bd868c60dde87ef3127ab" },
                { "ff", "60bcd5536c7989a9388f0faa5d7947a44b87e601958d6e40928daeea1410a7524dd7ed49ada617f6737d05c95acb3cb3fa9a1c977e2bed9628200562aefff03d" },
                { "fi", "331abd8f27786ffabe4d92428e7ade9f2c9011b8f77f99901086b0cbe4f6df97fd04f53d1924170b0b47cdcbe7d35dde46e57d576a3e13cdc9ee90f0c482aba7" },
                { "fr", "6141c395973692f8a6a1e66bf6f1f227a7f3c3678b4d49ad03d5d72e531d7b99b612345de04c99a5885479468724f50edcf35304daa7c9c2cbe54d72fe3fce76" },
                { "fur", "ec962686a5dba42017cbbc78e5266c200d021f483842fefe21fef3e314923921b3761a7aae64dd1c7811904d82e1201db52ae08cd993b887540edd8397e4de97" },
                { "fy-NL", "e9ec6089f48358a39a3dec689b4d977216e65c821308b08bb4325ef75bacf2b295f09179bf2e6df0b08da19a01272f7b1fa7bcbb781339ec2e8d614b1e12c656" },
                { "ga-IE", "9b6dac6fcdb7461ad51f8800675ba5403f42e2fe858bb331489be7b261fc40e8372d3d38bd9637ccdaab0b878e955ecfbf9b2ac532206b91a9a95c0a94834db9" },
                { "gd", "35d6c00291f677c6d3b69569c25dd5d3f4f6042960dfd7f6551001d3809db35ff58ea95ab0129fd359fc5a79a48c7e5579943141aa892a970e9466c5a19d9ab5" },
                { "gl", "1881209b67fe528dac4c8fcb74c3a5e887e1911ce7ea72e9e502ffd00d5bb0da286e438157cf5fe2293dd582898ba77d3b6a119aabe20b50826debf05cf526ed" },
                { "gn", "894702fffe46eb4d1d618a5254476f7a43d2abc5e90f4b9976ad92c44fc748ba2790281c7fe00b2bec87b51f921f2d0296ecea99876ddf4d338fabca5b778a75" },
                { "gu-IN", "49427f69dbe3fbcc61a501f81378ebe04cc6d8c24eb21d82d75f4525bdad1a64b90825744b60bdde8861e2ffd8b491742e22e05bd11e86b84440d5b1526f26b8" },
                { "he", "a26a4abc9d49264ad016766bf044b46fb8321a43bdd68aac0c8be434d3d187cc8c41b8428b021ea4ebf7721ddd6456bd9d09dbc74d91ed3b2624c11c01b2c740" },
                { "hi-IN", "6ef93984f81bb6157875fbf1c025406f4c39cbb5d1fa0b8f78a65543a0123cb6bc5fd60c24ec031c55706aa2d33da29bd50a07303d10e3687f62be36461e308b" },
                { "hr", "4461d61de81b73d195eed7d479543358a172d59d488e99cf6ae63b0dbf0639ec9f84273f390edaeb5bf6b16dc89c29861e71d8b263f6debbe4c6da10c6672a1b" },
                { "hsb", "9822714a57702e3d9352b3e782c3669cc79b91a260f1b3611990bc8b766843616aa37b45b365ba83ef31f070b51f2537ecc42e8d7629c8efcc9abc69d08d8a03" },
                { "hu", "b83e890605fa464869471939602e545f1945d401f75f309bdc4af8abaa17738417a24945ededd1e88827f20119aa22a4b66b39ab6f1c263cb6ee4acf608cd63e" },
                { "hy-AM", "5818f33f838ef7572fe88ead5d81bd0672f77a1b7e7c06adcc2b1aac1aa5b54305e159da6b6e20ef5cabb1e8906aafbf16a051088371b395898f80edd67414fd" },
                { "ia", "68c47c9280fe24eac88786de6b46190ae8fd571a98db9111d5af30b3a3b02f62825014669a5cfa1f71b5656a73b38880d9b910b76c0b347f5695edfbb21c1d84" },
                { "id", "341ba6d60f5d1a9dbe6d623eb2dc8237f1b2c8a720295937f648d83167c0055ab2ac50727004d16038ba57fd6e9c277810daac91555f8c53c8159fd313230258" },
                { "is", "c8a734ee92646c9884dbbe60d94ebd8581bd7549991f8aac7ec90d897bf0837b75cf30a92797202aee6c68403aba59091ff8d3259f4840d6c0922716fc583ada" },
                { "it", "c3a923e3ad9f8dc01784ef84beb831fa3362a954ff233d7d45b1ba056e4009e9345804a2afee6890d8a64fd9c0e8f0ae7eb4769f23a7f3063996c209cb998d67" },
                { "ja", "a6cf38fa50d460bb2c20704b3c7836156359bf7555aaabd44e2ef2733bd11e6b1f56301457bddd1af0315a0031a40782ccb20974406909528620eb85259bde2d" },
                { "ka", "d2531223112d91dc5bc6985792f32654dd294630242c7ec200d5eef2f479a49fc7e15d740283ba7f2cc5f1c371dd22430a552d0d4f660657e56f9553a6f2748c" },
                { "kab", "f9ff9d84465aa9a620d577fba8c052540d5ddc10b6cc737d87c1c6503b7f231a4eba8a5e130c8ccfee573030908773b41f431405d3689af3129053d18df78ccd" },
                { "kk", "3a257f29a3fc396bb656a32f5dde31e3759fd8bc9e7e402b0ce30a36825f082bde139cdfbde5645e3577542bfefd06101b3736f8b565ef0d3cc16467ed7c0943" },
                { "km", "ff079cd9eed6c916020563533954854cbf5a5e3b85112a073d5cf6eed58b13426f2c631dcb4cf4171e11adb5d887218c7819e5351bbf1450ef39d92878c0c073" },
                { "kn", "dc4bc45646bc50ead225be2daf2edda27f4e8d82808bfa8c46ddeafc1bed3ef0290488b8dbc65f2f145da8bc916d17ff5ee900e8e74c67cc62f5210ceb9a93ee" },
                { "ko", "1f73809e0e0c08bdbb34cec77277d3f02f9ec2001d1bc20269152091633b7d802c9ec7053bf392201740b28f1185dd100cef9e5d7008339b2a441e7c3bf93455" },
                { "lij", "ce5890857bfea7cc57e658bc157716b6efd542961480660d727a3b94f27a15792b09ceb5efc601f52119db9a9766c848b97c60f4d7279600c59c0d04e73f2565" },
                { "lt", "788432ade8430ef1e93b6f2aa6bd609abef198aee471f4b7354ad1c6132e6f6e19917f0d342a65cc64f157e6ade26399cfb0fa82dce9d5205475287752ed8ab6" },
                { "lv", "7576b5657a6aa0ea20a84b4fb7be972cc3e95106b96b548667327a4b3465a370dc42518f05f0e0c727983eff006b0df15822574c5b6f0a964c9d7f7a1d724753" },
                { "mk", "0722f6a556a27e04458e8b9b36b292e02fd1013abe417adafd602904910e37e7b51261453c47b94f08e769135421e7dd12fc3ab8d4928367561cbb065b6b545b" },
                { "mr", "feec0d802d22b354a6ebf9d00cf035f3f58bef553e187a8e9587d155d7186f3ee56e7b2e6d30ad28d6b4e009a98ce13958dd3f1a11856b70f889e6271a14e8f0" },
                { "ms", "d2d658cf9cfe36be77a0612dce0dbe42ee94df602d98bc15532478cbf3447fab1a5137efa46c093916a601efcecf1339a67fff2ba5a33deeb2f499199bdd9436" },
                { "my", "f02aaba12abf0d7b52aab9da11c6c06fe1842739fbca02c15bf082c0f7a7e3cf6186f59b6cc1b5df971d1fc2af4f922e688447ebce4ef9d687e696e0b222c276" },
                { "nb-NO", "348323852860934f1238ea38d867c5673d6243892e22436ae80c4ec2f31d207d579f237287c37cd4a42403116554ce3e8c1febdd3bb021b6ce604ec226573b55" },
                { "ne-NP", "0cd73bf777d69c0f1d8510254b8d0aa489f0809f10b895a6cc70380d5e35f5d9bf561b275f569b75564c34036b7c3bd97b9b85519a912fd51e276300db942c5c" },
                { "nl", "003cf69d55a5878ab4733eb5da967cd471d9f694f4c94ef9e92a02078f09dbea44431e828e954310a3410fab74c4c603f356b657754c926843a44c49face84c3" },
                { "nn-NO", "fe94cea4d317dd462729a4c9086b30b4c7ae5c453ae2ff589b6affa93af89f4766f47a00708c4c3d86cace0466f1a8de986003eaa318ae0765d70e32bda6be8f" },
                { "oc", "58b67a687f03077b6473f6b0eafe76dea643f4ca9b4b2e8db688ecc55128271d63e501aafe28fbe3c3a8ec8bd07c4253ac278414cf063c77309c1fed8c7a0b81" },
                { "pa-IN", "c44788183de825eb40755c64abb09f4bca14caad0d407a9895b181dfc49be08512b96a8a3e22672b1c71d731d480ed24207be6faeb5b6cf8a6ad92fc221c95a7" },
                { "pl", "ccd61a2bfb4a1eee3363f389d9fae63e1f0aa5c4d8452c9f7fc6fc4c539216932040706fe62bce12db2dfbe73ad7161b8843b086f6121c4d1c9b2a40a0ae7c2e" },
                { "pt-BR", "4e9e1b9ab9aefe9e6382ca8cb1deb379e58df3e8028ecf67f944dc3e6df3d6d8aa650e24d489b639baeb97c9a55d6f1ab7d475a62ffab5680619f12248280462" },
                { "pt-PT", "831b87a453b080750cd7001c01095d0573dfff40fea42b464fd8680fc7ef183bc603f9475a70cb7df0cb6a8c2ff3a41907b450d97a1b7aad5174a000675318b2" },
                { "rm", "68247728f891486722f2b9dcd183456da96d9292adabe4aee13652a757a1e0dba77f6fb4f59727dc988adf7c8b095e210048773059f0847cc6091ea7830aa686" },
                { "ro", "0b67c2063a6d268b01d68f77c262d05b16a7668778d38b63634a23451fa51653b16523a239feeb9cea74292a349763c24089671e6908da58ae9077083ffa5526" },
                { "ru", "c482c7ed21d78d3f8fef3278974ba6bbfee5fa786c37825ac20ae615cd9db2e0ea6ff5e5006bd0a766e56ff50117785bafc7c8a5c6c119807703c91386dd9bcb" },
                { "sat", "9e36a6ba29ea04bf45fbf669046382dcc4a8b93ccf2a19839f0dc2b95f2325cccebf31d3f2da52b626d3721db170abf5969645d7aee1bebb97b824a11b1b33c9" },
                { "sc", "2c505aa3be6858e77a8426c18795830c4582dfaad3422f9c9d205aac0426b8997fe65ae773e2dce54055790bfe037735ebdc8e68006c3acbe3e4c5b15d5d0147" },
                { "sco", "cbcd420ad7533a67cc8f9a376206748ddbc51d3ef8d7cf6ef809aa376afc0010a5c2329e9e11e8622b9fa5183b1f321fa5cb229dcdfd02de09b194b6f6106691" },
                { "si", "6100c16179fced8d49164fb376ce2cd5736176502554e7f58db240e02dbf0c45ea305f2ccdcf609a63f889c7cd333cec9716b7cd642b7477f98ab91ea8bcd893" },
                { "sk", "dd86ee650c6784700902847ded78fc7d01fb44bf97a43994fa9405e73a011e59c7ee7c366dc3eaa79a54005ddec15f448b4e2efa765448947046c8039ca3eaee" },
                { "sl", "e437d419690fae04d7f7b0eea71f7133ffb851af50ad61d37b6d8ac03d770985575a82420eb32c71e5f9e71840b5b5d6f559dd0dcb5104a6f0144aba27e379a2" },
                { "son", "96661788a48c3fe046fe5cf3df70fc7df0ab9eeeaf9f84159e8aaf561de2e081110d24bfe1cf6a7fe11cf2f0ce15d9d2d717165db88af3c2b0dac429c5e4c372" },
                { "sq", "af1e9c6f32bf66bce108a6010cd8b545bb6a58e3e229e5dd3d1197a70fe9d0524daeb1e857276122fe62845d42daa174a678b96e251f40d94968e592809b3836" },
                { "sr", "f587328258638585bf7f74819e26aa7531cb3d3ba38f56bf10ed56562293d1d8be91cb7b15396db9d49c527d9d09760ffa924872292e4af745a8ae8005fc77a5" },
                { "sv-SE", "890d5f0332257ee22336692184cc7a8986c425ff5a4556574cc3133aff19086cdff952c018a719048fd8c1248a4a9fa8c5acd4312d78bda19aafa96e612a9e75" },
                { "szl", "66d8e0862950cf7f108bf2672b8b1082efd2d6a6709233d0fd42c6e4808c440fb9e42ec04e4f4d43f21e2110ff706cd7bee4d4146bb65251d22ba1db9a1c6613" },
                { "ta", "f72bf885b14113d2ff7be00d87819248b9376893e16e581a8ffafb02cb25bc59870bc6e9ff6c516918f063f4d225533a06c37794c7b45e108a17091728744791" },
                { "te", "369c9939918fee8de3717417606e6870167cd157017cd78162496041241e85e68d12140cd91d45d715872042592fe6f303d8ca9f829a2d6211d9e6bf6bb6ae49" },
                { "tg", "092b64989e22d6d51e8b75987aae6dc5d681c8c1b485d44f2b114f982784b7c6ab4bfb99c7da4c7bf7070a090b1fab1f3fbd0f4b0c039ca462e46d477130ad53" },
                { "th", "a3e4f3bb99ef5420ca105f7383f35ffbb9f77824319d23b5aa19a0ac81b261f9d6305dd37d4eee69efd99f7d930e6d223a8432116685c59cb42fb2989797c01b" },
                { "tl", "d2d75c8abdd62ecee7ac629c0ab3187c20a0bb0892c7527999e7f68ddbb2e28af9fc3cca2cc1efe6550763bb2b2d98acbe1a1196d6a03966863aece5ca6367da" },
                { "tr", "c306801fe5c3f653b4b556797ea3171ca5cc6040f40cb9db2aead876a7d8513ae8322b6b80508dcd6bdb543aa256637a6546864d40cbfb217beb1d5c16e03a0e" },
                { "trs", "08ab7499e34c1d6af138dcf03dfe40337b53277722b6eb880461104d0087bd18bf33bcb7f3b1e89eba69370f716f6a7e6900a5b58d0f4433db9f66f8e14eeb5e" },
                { "uk", "8d89a6b39be8881c43b1586b5c1e6b8a44624340ca94e170384a8193af80afd0f8af71e64a9b0ef75171855663c4924c79b9a6ba3c1aca6b0ee89e9d2d13ab43" },
                { "ur", "62da89e7d31a5646f5196116751192514473f48e84e9911a3a8aff136ff3baab16a68cbf60ed5e713f4ff0d5e6f7d30104fbad9caa55023b1fb71dde953e5103" },
                { "uz", "221cdd400b007361ce77645b4ad29c6448d94648f394dd6d099dcbb42332e320853c68b8fda1083b6f048f75f96dda9db0a4790efcd208a4a715a4905b24d379" },
                { "vi", "c9cf7db4fcf6ce33ad2fe2e0c5b7d14117b3d28251cfcf44774d66753e44de9181b9ae63ecbb988341cacfbd0d74df45e7612303bbd6fccde25739b0b43c7a91" },
                { "xh", "e336b9de8d54ad4a435f679163c55e1202489ae0d289cd871a5d1c2994692a640a25ae208f9a6646fc32f63d541c24c99d92e0de02e0a4e284eb92ba17905de0" },
                { "zh-CN", "a7281915769cdf5b1e83fa58e796d21592f5890d150344278f06fe4cb92010fb909ec72f01f997ca6f55037684f28ffabe26052ee56fa73dffa0da8238472283" },
                { "zh-TW", "d248a578d688844e5b3405bedf74f3b1c637d0cd5ed1ed38632e3ae6ba93dd47284e6703ec8570aebe94d5aa922764a315c9661949c240e4a039ae70c20b41d7" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/126.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "6488cecb4ac766c7bc9fe389a510c72d4841218c7e7e29acb54d9e8289e8eb067e1fbf494abfb1e96c81c997be728b954752c43950f5eafdfbb7b0d0de9b1914" },
                { "af", "b9d91ebf7e6ff09eb38a1e4c09595f8f0e9abf646c8f8c0e6a5b764e279e1e8fa17032e5d37b7a2be3466ff1c78e1d06f9f462c7030860ac133aae8e13b9b97d" },
                { "an", "a6e1924a5dedc83e447f7ab39298f03e84be1d9b58df9c995b6e6ff18582ebf027194ecde11b6506be23ae41c59e4234901c6487dceed1b5881ae27e16b18827" },
                { "ar", "10469fc2cda2f65843e9dc5dc0e24a346ea36aa86ae9409557eee91a9ca8e3f387b22fd9492cce4c37bafa3abe049552c66faebb6776b27804b5908583fcabcb" },
                { "ast", "84fd8277688b7993bccf56f8e23c273c0247c5e47d3e32869000430a2eab98af67404c159935a76b240167b91339773f6d37e92a3b9e30ac13d2261fb6bdc457" },
                { "az", "63a18e4d9f00df3d1b5f312775180fb6fc3d40f14b4706675155e9f0f8f461a3c2225ab1fe55d19cf3796a932d3e52c881a7bb7a892a710c447c2a3f1a31ad5d" },
                { "be", "7f163c8df0b043510e3c0c0f99452772d34373cd3b6f237330c6ed0e29db67307491b6a051ee417f28f814d0a624c825041b2565dd558be5fe70e5fcfcc44f63" },
                { "bg", "742ed5cc31e6671e298374ffc922f35f82ea0101352b85e142c37a43f1438f29cfe429ed427195a4050b461a3ebb974992a4d976907d91f7213866b06e283733" },
                { "bn", "899dee42312ad7e56a0b62d48efb026867f0a326ff15141298801b5d21fb433eb4de284fc760996d2c51fcb5675f115fbf0f39163a424389ed909f1dcd1ee002" },
                { "br", "6b4a9979c50110350c25a871f9943c56faf1b9ea76c0d0473001458b2ecf61c635943e42ea3aae14e23264539e090f32ecb1054bec2d54467dadb0cdf4b68706" },
                { "bs", "5ea2edcc7816b488782b06120dae49a3996e23d5fc617f363c408535fa17fea6ec7de78f494bc4c19941e8cdc10ac786d9beb7fd589a761167ad4369f76bedc7" },
                { "ca", "f31dc15a05880e6ed0e2008b69c2cc0cfe2c3d2bbca8dfd0df6b3f489c4910a580c54c4217b283e0a3b523a24214c104a595acae75d59dcfa49857b7ac32bdc3" },
                { "cak", "5eebec276587165c75c64760dae10a3dfffa9b4e4350e96155b66ac7c202a77993adc8e43a342237ad31238970ba4b2d9e1e30225283d9cde2e99577869f37aa" },
                { "cs", "16d4a51152b72c9715968ead9549b8f1ab6182dafc22b2936c14c4d164c314611499b3efba869d90cfd9584e9f8b69091d09c33d9045d1dde54bc1f22d0cd0e5" },
                { "cy", "52e432cf8c1dd0d1c94eec5bb25fba3d131e8bd040fc893ce73ea375945831dadf41f681be31fe4876cb0084105475318921380eb3f9d5ece102eb742b466a66" },
                { "da", "48e04425fc954c6441f25f99795274c27bb568fb8478c7b204139da58832d159c6760fe2dba35b13737f18af2fa04c93c2044cddb1a7bef97acdc91b4ea26626" },
                { "de", "708d6556ba43b3352c2c68c2472f3780552d07ecf968781e8c2dfb59049fd1144fc48ef377c6b6db074154d7f239235f83326bcf99936f5d2ac6efef4689ef8a" },
                { "dsb", "8eba0170e7c85654aef24a1afd0b5ec67d84ac8c7d8821629048e47b9459920022f0bd3a08d62ca00f81f1d47a1d1fbad7ea6d91f48af4f06c7f6ec0305f54af" },
                { "el", "efd44cfe67499bca37577acbd8e4831875510f6345660fe9923be047716b0034cada8e04ae8f3246cb21251787fd7f39eb4a9c924faa8db17c5314cfe87040ff" },
                { "en-CA", "ef4b5f0d13ecdb858b3aa9147b2008267e1d662bd421963907386d16fa80435468bf4876068a17e06e9256fab51260622905cd46cc8b424595e79c186a6c5768" },
                { "en-GB", "97e60bdd8969785ae39db1e10bbf59ec6a8eb46d874e46870c57fae86d14562ed610fd4ad5fda416e3af48aa9927af57c53843bd5a59f0228113a76916a9b7bb" },
                { "en-US", "2987cdef376d6963e80c5037bea18aa2323fd87816cbd9bb51a4fd098231fe8af17b9b7a5f53d484c4601d45a786eefc61e08475334931543d5d1b5d7fad33d5" },
                { "eo", "aeda370e2efef4a77c21b16c63fe700fd05519e2cfe1045217e12a1e3c053b34787ff8293bddee5e8c979690024908afc7c00f847319ad8b2445c05f21dba532" },
                { "es-AR", "97f6a5efdfd8d250f38d7ca1ab1518d6aaf9d6e110c2d86b7c9ce6623b3d8a28c80b59ea85cff250c544eb842d079a0f4728797c9adcb11a14f11af45bd4e9d5" },
                { "es-CL", "c0465780da1af3683e0980f626f939a7c3a15b3c79e0c8d18376c26614b75c3b1c9001ef692df756b4033ff8df4cd7a52ff31d2908126355257bd52c726a5da2" },
                { "es-ES", "b19563d89d881542a993974162b37ffd7ed263e9516d49b5eb9a09f263edbfeec244187fcbaf21bc35a47ecebaefc34cc9f936720272b5320bb73892aa97018d" },
                { "es-MX", "90da884e693a588cfb639df2839b607ebb07f75680a98ebf08def888530043a08e3d495df7d851ea17842472dbb5ffd5f006507710c377aa5636521155d2b1ab" },
                { "et", "f05718e9696034461f77482ea9e9666be4ac12acc5b2782bd3fc272ca65612f06007f94b451fb442d1d972fe8953455feedb5254fd7ed47104c6834c0a8160ac" },
                { "eu", "d85b9a4e5388077b14a7612abf3d1b3f285718ed77eed1011aa483eba9c93ce0fe042bcd478662d075bca831fc802df24aab6251f0ce2bbafca91075a4bf2eaa" },
                { "fa", "ba6d367e42251eb5e6e5934ff9a76688815426fb03e46628956394242b49ae0653f4f222d79a290fb977a5eb63b3d6e172ad12fbf3182722e8f2dce6f19e7876" },
                { "ff", "84767bc226f47089a987000d20c2f7c4e3defc057ab35bf66c55588f61664da771198fc548996c7aafb181b41c2bf8483affab46a0ddc32b73374ce7eca5c2fd" },
                { "fi", "091de9510a27888da299a5a8c79603d140fc385a7f5ec2f6082174224b61c2127495d56cc9b55718ec23043c362f9b92e41c542923e29572a8791cc0b2ac3716" },
                { "fr", "25e84d18158403913939ec98e76f17fe633e3d21c21d0df967b746e7cfad5f6b5fabfd65d6283b6c0693f3e196a5edbb39e224809550832f4c5520cddf70d3ba" },
                { "fur", "5ec9df1c0ff5a0fd637c135d1d9adcfb5448a058ed4b80f40f29a19b72a98ce34fbba6d64ca8ab16013ef076ce59987e14ad37a3edf52e281576ebef73d652c5" },
                { "fy-NL", "57e8919565144577764ba45823aedc6c8abacf04cb83fc67056a008997724f6964977a84434416961abf374a69c171362bb25dca8ddad82506206d2df68d91df" },
                { "ga-IE", "706375609b7e33bb1d208a9ab0445b5dc67c9badeac3fd0db82c3d24b7e435843062965df2bf3634d7aabc022de50af71fe6c8eb01d80902229e7d11aed32d04" },
                { "gd", "88f92decfa07ee770ad175b9b4a43a21bd7e14ba0d6fdf4372702ff427eb4229f6c9079fb044037eab4b42e01aec20ec99bc9888aca3266115559fe859733ba6" },
                { "gl", "d7c69b95a39a9d449f44aa5c09a8e21b452c9cdd7752b127cf9d77cf208c03839d28140749b0aa85d76afe388d7ca573c567c00068ab1683fe3ab5bdb1717022" },
                { "gn", "d349ce566d69cf87801c0c31f423ecc598bc84598ff454ab92f43b5d9bedaad3ce5df9fd037ca4463146bcd904cd9076b0e3a1e75b066ccf0768930f26381522" },
                { "gu-IN", "e019e0a43bd836c20cff53a0c8b0dc1f9847da89d2cebed23a63bb35fc154fa12b7e8d3e5bd26547378805aec8d4e1f21b39bc78a4d8a4eeaf19f2635909ccfe" },
                { "he", "3908299679ca87c54665ee355c82f490b7280861370cb311689ae8bea19820b1af9d70eb40f1f32ebb207f4c5a653e0c02a8ca97b178230822b0c4cafcc4afcc" },
                { "hi-IN", "03bbefd3c2ebe2ecf61f7528e702c2f74d469c4c0fc38fda423ba3710c26819660b28d365b40af6aadf60d29a4404b36ade393fd985083705becf22a26a82a08" },
                { "hr", "a14961c195278685e2ca4a24c1734f4997dbdd2609d47c8dbc06c03ab12cfbcde9fdfb657e5c81ab55e34b96ed12a3e1a2d131f46af550ed0e0c83e5c34fadf2" },
                { "hsb", "85f035ebc1c0b0b5adebd4eea99144657dd2d393680ffe6c75088508bea8f9082480bedea6b0b797a688db8cbb8558ed00e4f1b7dbe6431d0853f914b0712802" },
                { "hu", "049e00588b2fc1a2e07907e07e78b9b2943d2fc56aa396b8bfa998bf4be57c6edb9987cde1d6f94525b45ead2b2bea01a403287b33adeca215e17dd31e90d945" },
                { "hy-AM", "6b61836e7297359b35486c88e7fd2d68149bd5e2b947780ac83971a1706bd0856b0c6a8e3bf223669e91e3e65d7160e920bf89c85534cc494c09b6ab9df6e406" },
                { "ia", "625d4dddcee3727cff6417b0e92990caa3827331c386f6d8d9927c413f867ff113a32ac31464c98a303722395e94aa8edf1ed6a8daa6d5c2ef4744ae59dce64c" },
                { "id", "9a49a52b6320fd2d79f22396dc4b3bc62fad7394a3df59fd5294769df0931d539648a1dd09966ff5a079e512c724f373056d612981b4e0ee6e7a395f0235abce" },
                { "is", "f22c9ebbce40d7c38f30a494e45e24f38a853dd41dccb44a556c2dc2df4469144aa84786fccdb8be405117f41158df13e1248fa7f4dc6c7db97ea06ba8cf2aef" },
                { "it", "76aac31ae7ff5f196f8637f575cc3d083949c14bbf374e7f4e16c1bfa3c1f6ed716b12cd4c7c9a62b6e1761cc9b002a7539268c84a48070bad9dc57ace57d260" },
                { "ja", "d0d37c88ac8abb0fac08246b2e4401364a6a904e07108103cfb87235cbf99d44dc3f81e75168439bf4ff599b6e87b34b99fcf680bdce9861aaf18789fe7f7a53" },
                { "ka", "6a6e5c2c3b0a4317017cf3100cba2b7babcb081dceead9b0d83974e6809e6f025c162a1c27c6a2d2f670889665e3d4daa0108b7ba3983e4cf426a6b8728d0121" },
                { "kab", "f73d1c3137004d1e798a182568f2ba4135351a2defff7b1d7b71c9a32a240d1bf892acf8968264f8823b7af9905f7ed5da4b540ccaec7f361c92b9fa3a950985" },
                { "kk", "8860c71d42c43fdae75c41667e249bcdbdf89d06f768e37f522aaf2c3b07f11f8549059e66afcbb3c9eee26eea0e3db4261160b67b080ea57bf78df1576d3986" },
                { "km", "42580df0f4e7bc127346240c42a0f6a44440707c8d5a4219c868254741a5db78ed7c1b98b65c707ac093f378e42bb0d236565f1cf7b9629de2e14a22912beb91" },
                { "kn", "861a4669d9d0691fd69f6ad8bae00e3cd9764a3d0bc01bc16de0d09b90a6f04ddc9103e254ab43c88d838fdee15c643039eb0a302463bfa3cb2b5636e1dff1e9" },
                { "ko", "8aaaa88038faef5edfa8d261c37cf004ed88e9a8302ff8778cd7f659b04e804712d3c0bf8a365fa76404e6eee29960a4fda8e651c1e9370d79288589ff1e316f" },
                { "lij", "e0883dfc96ca012f6716c86dafc6a30740655861bd90b35ebf733ff9dfc180e15df33157f9380a375e57bab001adaf2e293ffec6a287877ae2915c3e81375cc3" },
                { "lt", "50f82323e92c8f14c3d0b5f20fb36b51a6872cfc6fb1db2ddf1de4dd115c0a8a521472e3e2dcff490c985110a529b5c2ad3a7777cb9c6bd3abb5782c3124eded" },
                { "lv", "bd75c09edf183993e47d4c5623daf49750d22a3239abc968b1eb5ef99a7421428470c4d9adbe2334362939cc10229e51c3eee61f1535f799902d6b9187c31563" },
                { "mk", "36f29387abbc2898c63da0bb63ca62a49d39c380ae35ff5f028463c01402c0d0d030364365ff93386b555ac48ecd182f762312d9b60e97ad36412d784989b90f" },
                { "mr", "cce013639e14e75c7a47e5d268c191275e6b2a1c60b8b32ece24c51cf2a1c9abe7f809b801581187cfca7e36487c2dbdeb600e20f5ab6ffaded69f56d139cea3" },
                { "ms", "c9a3c488ea93c30e06283aa0cec8eed23a03cd40fe9f64e4e95801d0d4b5b804a930371cfd6dd8c35e942d71e4bed3cc2ade50fc31ed53e4bd56d8b3c8d226ef" },
                { "my", "c039360d65fdc0ec002bbed6c30251d13f66d941a817e98712b38b977b97b6c2e6db6e662c00be92c5e7e3aa43160e65f90051f21a2dbf91bb5ada5fe5b8ee33" },
                { "nb-NO", "ec34efd5d17aebd7e8db8babcebc8183a3428e4e802f29f49992d988b2a4b96c942815377fad0f4d1ae8371afbccb6995d7136e245b2c280c1f38a7e02ebbefc" },
                { "ne-NP", "154abbf49636ae287f8cafdedbe4f910da0c6a9293b8227ec1d7b2bdebfb1ecb95f9f86a1f51bffa641ba803462ef4211e37fe0b31d6a4bac6ddabeb1dfea9dc" },
                { "nl", "21c6ae0af24460821304b87bc0460ae19922bb89f17913e4434eceea8750c018b81858cb9189a698239e445ea80a0379938414e33e782c3bd7542d69ba5332ce" },
                { "nn-NO", "443800ed9df1ef98b5c44fce31645a15b78f222aea9c14e80b5d55618b7201d63cc5df713c41eb8b04c5cdac89b45c21450d74e2482194f0e03fffd78b6cf135" },
                { "oc", "2376bb3b8c04c5a6c4d0c55b6541de5d3ac0eb8be8c14303500f07c560f915b1856639cf6d8735d89f74a50f1c453e086eb9ee3390d61ae0b01c2b2cf21d48a9" },
                { "pa-IN", "3c885dbf653a2c91c95005f05135aa3cf100f844fb0ed1c34203b525821cfdc75859fbfe20b8f930636d773235acfd45ebcd3f5bccb7721199d278d91649e22c" },
                { "pl", "f14295eccfe713efe3fb2bcef862ce7bb7f281088e25d16b5f5e06998f610ab27ab06961ab149be9e6c9361a8761ea2beee3c49ad35111503a6f6a66e7823067" },
                { "pt-BR", "418dac7c738dda346ec4f6ac20d7baab22a20145bc8a5fbb045d5872f060f97c1125171b04fb0ece32392743e8d84c637c8dc78b45fbf0d7cbe72e4fc7d76987" },
                { "pt-PT", "364855020563ae73d32dfe0dbd4bba8f26695c5901cbf9f0348f2fbace159251eda967828a9792418df0f61fc9c1408589883e49373de6f434bf8fa85500d144" },
                { "rm", "3a028098b53cf0467e972e20330b819526c94f2f93b8e3e21101c7e2fbad0121a16bccb8ffe6f48374b54bee54f61fb62387f1e0884a04c15ac0fa4e2089a778" },
                { "ro", "877d39dd0e551d8a4fceb5b204460295ca22c3cb194fcd169868b52d0661203533754aa59147de0ac903fec66327dce039472bd1c76cb7d7a478951f0ca9d8fd" },
                { "ru", "1b1fcd4a74bc99fda6bb35a30b392f5b116033d0939396f88542c2cdcb54b4e6f36472df207e21dadf8d806a176e6cca680e73f9d28559829a6cb244bfe19482" },
                { "sat", "e9c7b6850a4df7ef939c8f240969a638b63772dc500a14fd8adea27031c7aad9305b72365848f1024d9531bd22df31ee7bdd360f8dd9c8e5f2d2a705d82b0352" },
                { "sc", "5d5b45384dd23c404db9f194fdbeb395e32b23bdf68303a3d9acc3aa297f7d0189014f8a1d7e1477cd33b752efd2f223b59d20793491f3da32d1ce895cc6796a" },
                { "sco", "642ccbef6ac61588626919cfb5d0d49bbe583237df78c28bf3956389a07de11b9e4fc903047d0f281a5aca8c2b027c37fcee90261d3202b67f2c3261a371568a" },
                { "si", "b74919db7c8bdf3385c7c373afd3cf542bd47d74289f9749818bdab7b503f5c66452b3b2a20f4cba96384c75c95bcb34d32670e845638e3d3dc1808e31308472" },
                { "sk", "ea79a5b2e6075f30cf95db0d2d57e7096f1d2adf08946e946dc1b90acd2b234a6d684ea36e0fbf3e08ba8adc196b361ad307907b5c5198941b56580693857182" },
                { "sl", "515ff7f6b8b6611458ca3a0a3c2373bb3d2c6c90b7580f0d6fbb7dec107dca6cf7fac04b534cc3ae4370eff6b420054cd335a2f2cda09f9eb66f90aca63430d0" },
                { "son", "d01a7332dfdbbe69102e903031240834bb19632d0d62923b737248185463806b686a4d65dc8965299a7ae6a7d530a8cc043cc31e8ab4c7c57167c935f076e42c" },
                { "sq", "fa4b141844d09219a69f9fcc5760ad8ad2a82257f05245bf8b6f2277360d2e5e2bdf87678499361e57663761322f5bd337322ed38d4f48e3d01deed6b50fdd3d" },
                { "sr", "723bc24422a3a1661e366dd89cdd85348371f2ba008aff74ca2085eb3331a7dec3259a227cc41223d2d63b0e8abf06078d637063fc44c92b286179ef56e24698" },
                { "sv-SE", "1d5fdeab45a766f28292a1863390b991682b4c3e8d3045ed92dfc671708b20719ae413a21c93c20be05dfd3e6d4fe81c90d4cf30fa7e41fd669748507de64208" },
                { "szl", "6f4a5eac5725203fbd419711929acfe07a9a4dc5ef6a23aecc28231159365901ebefbc434b5499b586c50c2bae72ecf6d86318d0e0ec80ff5e963af9bf473c98" },
                { "ta", "abea66638d92a85ec41fc0a0246a031d25bf3ed0632622f8c969a5c820b35be13499642d1b20891003db748779fa56ee7957001b376234dee81c64a98dc34974" },
                { "te", "4a983992b695531b4e0971284f27d11946d3839b105b428ae5cc345cc27cd1183fc82fc4dfa302df035276d32c2282b3340d2a67f8d73b1c05a0dd8ea209b2c9" },
                { "tg", "749a4dca355be02c20ce83480a8df6b7b15a7cb0ba09e2d196adef22559a6881c48040dc654d0cbd19451366e39a9fb0149d3c07d48d0b696344e6a6a57ccbca" },
                { "th", "f7823c600e5bedeb2bc41a82bf7df124d6abdb3d3ea5be3efec43b5675f58e5789803e85a4b5f54fec3d4642ee758cf667c26596a3eb0e8cf5d93709bc54539a" },
                { "tl", "f9ae71431b3f179def95eef35d604fe35b2908b1fe2079077e96e6b7bcd0fd1aeae41f9e19a0b87cd3ab2145e07a9cafe0425df03069231ed58d0404f763216b" },
                { "tr", "cb2df2ed1fb571690d08fc2d9b85c80c34ab2f057d33fe5371b66684c93fd1af6958b37d3516bb2327d8c9ae60b6cff5c9101b511fa9052db186a30e74a3f5ec" },
                { "trs", "794cf8628ae96004ff31c44f83ba04a0f6314422a21575a9aca6667a5eb48b468bc42f99643e02ec441636b2da0126c9dd82d460e48e51e1c327b332d12ee196" },
                { "uk", "11b5cfbcd387289bea4720f13d2037fbc53addf09e0f8ae39c027b77a15d04615cf5b43e328fca51819c45dc4d23c1266382a102ca036d7c853ef66e1fe717b9" },
                { "ur", "3baa234bb8e84773e5b436a97da0831eee4962894e9dbf6a207b3b449eeaecfb104af903dfb8f88919e97eaed47f337db45579efd13bf44c269b976abb114fd9" },
                { "uz", "1444ff7e0957e1650ddcffa64b860ed678edcf1a95548fc736bad031d8e5637fc65b4210f5bb2060db32909207c6e2036861c424509b39b6ba18c5090a68791a" },
                { "vi", "a03d74e32a80c20a4def660ed94cc05b601232e51d2d61d6ac06850cbda065df9922ba8cffa59154cde170a1726b18c1fe72eba03a4597b57d49aaccfc11bffe" },
                { "xh", "7c3004d2b05c88c1074f22af406cb11ea407bfff21b9c66c12afe8dfeab055fbb806562b473e57f559187783405dfe53b5caad78b0792dfe2b0e9ccf700786be" },
                { "zh-CN", "42de5f92b0ccd2e4959dfc123281a56e6541766ff9db1d1ea289e35af0af95a1f72dece843de8bf272db67929d288bc8d0ddfbfb242e00df05dd267852a50a49" },
                { "zh-TW", "0d8b8c27aba540863a3c5fc0896fc0d7fc838c07682ed9e36b1e96a6fa190a4de089428f78c0ca5695ea3dcd94759cff27cc28f95e15946bca72e6f085dd7ea6" }
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
