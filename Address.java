import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class Address {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int BASE_58 = ALPHABET.length;
    private static final int BASE_256 = 256;

    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }

        input = copyOfRange(input, 0, input.length);

        int zeroCount = 0;
        while (zeroCount < input.length && input[zeroCount] == 0) {
            ++zeroCount;
        }

        byte[] temp = new byte[input.length * 2];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input.length) {
            byte mod = divmod58(input, startAt);
            if (input[startAt] == 0) {
                ++startAt;
            }

            temp[--j] = (byte) ALPHABET[mod];
        }

        while (j < temp.length && temp[j] == ALPHABET[0]) {
            ++j;
        }

        while (--zeroCount >= 0) {
            temp[--j] = (byte) ALPHABET[0];
        }

        byte[] output = copyOfRange(temp, j, temp.length);
        return new String(output);
    }

    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }

        byte[] input58 = new byte[input.length()];

        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);

            int digit58 = -1;
            if (c >= 0 && c < 128) {
                digit58 = INDEXES[c];
            }
            if (digit58 < 0) {
                throw new RuntimeException("Not a Base58 input: " + input);
            }

            input58[i] = (byte) digit58;
        }

        int zeroCount = 0;
        while (zeroCount < input58.length && input58[zeroCount] == 0) {
            ++zeroCount;
        }

        byte[] temp = new byte[input.length()];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input58.length) {
            byte mod = divmod256(input58, startAt);
            if (input58[startAt] == 0) {
                ++startAt;
            }

            temp[--j] = mod;
        }

        while (j < temp.length && temp[j] == 0) {
            ++j;
        }

        return copyOfRange(temp, j - zeroCount, temp.length);
    }

    private static byte divmod58(byte[] number, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number.length; i++) {
            int digit256 = (int) number[i] & 0xFF;
            int temp = remainder * BASE_256 + digit256;
            number[i] = (byte) (temp / BASE_58);
            remainder = temp % BASE_58;
        }

        return (byte) remainder;
    }

    private static byte divmod256(byte[] number58, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number58.length; i++) {
            int digit58 = (int) number58[i] & 0xFF;
            int temp = remainder * BASE_58 + digit58;
            number58[i] = (byte) (temp / BASE_256);
            remainder = temp % BASE_256;
        }

        return (byte) remainder;
    }

    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        System.arraycopy(source, from, range, 0, range.length);

        return range;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hex_string = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hex_string.append('0');
            hex_string.append(hex);
        }
        return hex_string.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    static String sha256(String string) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return bytesToHex(digest.digest(string.getBytes(StandardCharsets.UTF_8)));
    }

    static String ethToVlx(String address) throws Exception {
        if (address.length() == 0) {
            throw new Exception("Invalid address");
        }

        String eth_prefix = address.substring(0, 2);

        if (!eth_prefix.equals("0x")) {
            throw new Exception("Invalid address");
        }

        String clear_addr = address.substring(2).toLowerCase();
        String checksum = sha256(sha256(clear_addr)).substring(0, 8);

        String long_address = clear_addr + checksum;

        return "V" + encode(hexToBytes(long_address));
    }

    static String vlxToEth(String address) throws Exception {
        if (address.length() == 0) {
            throw new Exception("Invalid address");
        }

        String vlx_prefix = address.substring(0, 1);

        if (!vlx_prefix.equals("V")) {
            throw new Exception("Invalid address");
        }

        String clear_addr = address.substring(1);
        String decode_addr = bytesToHex(decode(clear_addr));

        Pattern pattern = Pattern.compile("([0-9abcdef]+)([0-9abcdef]{8})");
        Matcher matcher = pattern.matcher(decode_addr);

        if (matcher.find()) {
            if (matcher.groupCount() != 2) {
                throw new Exception("Invalid address");
            }

            String checksum = sha256(sha256(matcher.group(1))).substring(0, 8);

            if (!matcher.group(2).equals(checksum)) {
                throw new Exception("Invalid checksum");
            }

            return "0x" + matcher.group(1);
        } else {
            throw new Exception("Invalid address");
        }
    }

    public static void main(String[] args) throws Exception {
        String[] ethAddresses = {
            "0x32Be343B94f860124dC4fEe278FDCBD38C102D88",
            "0x000000000000000000000000000000000000000f",
            "0xf000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000001",
            "0x1000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
            "0xffffffffffffffffffffffffffffffffffffffff"
        };

        String[] vlxAddresses = {
            "V5dJeCa7bmkqmZF53TqjRbnB4fG6hxuu4f",
            "V11111111111111111112jSS6vy",
            "VNt1B3HD3MghPihCxhwMxNKRerBPPbiwvZ",
            "V1111111111111111111CdXjnE",
            "V2Tbp525fpnBRiSt4iPxXkxMyf5ZX7bGAJ",
            "V111111111111111111113iMDfC",
            "VQLbz7JHiBTspS962RLKV8GndWFwdcRndD"
        };
        
        for (int i = 0; i < ethAddresses.length; i++) {
            System.out.println(ethToVlx(ethAddresses[i]));
        }

        for (int i = 0; i < vlxAddresses.length; i++) {
            System.out.println(vlxToEth(vlxAddresses[i]));
        }

        for (int i = 0; i < ethAddresses.length; i++) {
            String addr = ethAddresses[i];
            String eth_addr = vlxToEth(ethToVlx(addr));
            System.out.println(eth_addr.equals(addr.toLowerCase()));
        }
    }
}