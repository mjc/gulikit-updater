use gulikit_core::scsi::{SenseFormat, decode_sense};

#[test]
fn sense_formats_and_declared_bounds_do_not_invent_fields() {
    for response in [0x70, 0x71] {
        let mut raw = [0; 18];
        raw[0] = response;
        raw[2] = 5;
        raw[7] = 10;
        raw[12] = 0x20;
        raw[13] = 0;
        let sense = decode_sense(&raw).unwrap();
        assert_eq!(sense.format, SenseFormat::Fixed);
        assert_eq!((sense.key, sense.asc, sense.ascq), (5, 0x20, 0));
        assert_eq!(sense.deferred, response == 0x71);
        assert_eq!((sense.actual_length, sense.declared_length), (18, 18));
        assert!(decode_sense(&raw[..13]).is_err());
        raw[7] = 0;
        assert!(decode_sense(&raw).is_err());
    }
    for response in [0x72, 0x73] {
        let mut raw = [0; 8];
        raw[0] = response;
        raw[1] = 5;
        raw[2] = 0x24;
        raw[3] = 1;
        let sense = decode_sense(&raw).unwrap();
        assert_eq!(sense.format, SenseFormat::Descriptor);
        assert_eq!((sense.key, sense.asc, sense.ascq), (5, 0x24, 1));
        assert_eq!(sense.deferred, response == 0x73);
        raw[7] = 1;
        assert!(decode_sense(&raw).is_err());
    }
    for raw in [vec![], vec![0; 18], vec![0x70; 7], vec![0x72; 19]] {
        assert!(decode_sense(&raw).is_err());
    }
}
